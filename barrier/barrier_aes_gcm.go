package barrier

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync/atomic"

	v1 "github.com/zilicorp/bull/pkg/api/core/v1"
	util "github.com/zilicorp/bull/pkg/utils"
	"github.com/zilicorp/bull/store"
)

const (
	AESGCMVersion1 = 0x1

	initialKeyTerm = 1
	termSize       = 4
)

type barrierInit struct {
	Version int    // Version is the current format version
	Key     []byte // Key is the primary encryption key
}

type AESGCMBarrier struct {
	store   store.Store
	sealed  bool
	keyring *Keyring

	cache map[uint32]cipher.AEAD

	currentAESGCMVersionByte byte

	initialized atomic.Bool
}

func NewAESGCMBarrier(store store.Store) (*AESGCMBarrier, error) {
	b := &AESGCMBarrier{
		store:                    store,
		sealed:                   true,
		cache:                    make(map[uint32]cipher.AEAD),
		currentAESGCMVersionByte: byte(AESGCMVersion1),
	}
	return b, nil
}

func (b *AESGCMBarrier) Initialized(ctx context.Context) (bool, error) {
	if b.initialized.Load() {
		return true, nil
	}
	keys, err := b.store.List(ctx, keyringPrefix)
	if err != nil {
		return false, fmt.Errorf("failed to check for initialization: %w", err)
	}

	// if core/keyring exist
	if util.Contains(keys, "keyring") {
		b.initialized.Store(true)
		return true, nil
	}

	// if barrier/init exist
	out, err := b.store.Get(ctx, barrierInitPath)
	if err != nil {
		return false, fmt.Errorf("failed to check for initialization: %w", err)
	}
	b.initialized.Store(out != nil)
	return out != nil, nil
}

// 解封
func (b *AESGCMBarrier) Unseal(ctx context.Context, key []byte) error {
	if !b.sealed {
		return nil
	}

	gcm, err := b.aeadFromKey(key)
	if err != nil {
		return err
	}

	// 获取加密环
	out, err := b.store.Get(ctx, keyringPath)
	if err != nil {
		return fmt.Errorf("failed to check for keyring: %w", err)
	}
	// 已存在加密环
	if out != nil {
		term := binary.BigEndian.Uint32(out.Value[:4])
		if term != initialKeyTerm {
			return errors.New("term mis-match")
		}

		plain, err := b.decrypt(keyringPath, gcm, out.Value)
		defer util.Memzero(plain)
		if err != nil {
			if strings.Contains(err.Error(), "message authentication failed") {
				return ErrBarrierInvalidKey
			}
			return err
		}

		err = b.recoverKeyring(plain)
		if err != nil {
			return fmt.Errorf("keyring deserialization failed: %w", err)
		}

		b.sealed = false

		return nil
	}

	// 不存在密钥环
	out, err = b.store.Get(ctx, barrierInitPath)
	if err != nil {
		return fmt.Errorf("failed to check for initialization: %w", err)
	}
	if out == nil {
		return ErrBarrierNotInit
	}

	term := binary.BigEndian.Uint32(out.Value[:4])
	if term != initialKeyTerm {
		return errors.New("term mis-match")
	}

	plain, err := b.decrypt(barrierInitPath, gcm, out.Value)
	if err != nil {
		if strings.Contains(err.Error(), "message authentication failed") {
			return ErrBarrierInvalidKey
		}
		return err
	}
	defer util.Memzero(plain)

	var init barrierInit
	if err := util.DecodeJSON(plain, &init); err != nil {
		return fmt.Errorf("failed to unmarshal barrier init file")
	}

	keyringNew := NewKeyring()
	keyring := keyringNew.SetRootKey(key)

	defer keyringNew.Zeroize(false)

	keyring, err = keyring.AddKey(&Key{
		Term:    1,
		Version: 1,
		Value:   init.Key,
	})
	if err != nil {
		return fmt.Errorf("failed to create keyring: %w", err)
	}
	if err := b.persistKeyring(ctx, keyring); err != nil {
		return err
	}

	if err := b.store.Delete(ctx, barrierInitPath); err != nil {
		return fmt.Errorf("failed to delete barrier init file: %w", err)
	}

	// Set the vault as unsealed
	b.keyring = keyring
	b.sealed = false

	return nil
}

func (b *AESGCMBarrier) Seal() error {
	b.cache = make(map[uint32]cipher.AEAD)
	b.keyring.Zeroize(true)
	b.keyring = nil
	b.sealed = true
	return nil
}

func (b *AESGCMBarrier) recoverKeyring(plaintext []byte) error {
	keyring, err := DeserializeKeyring(plaintext)
	if err != nil {
		return fmt.Errorf("keyring deserialization failed: %w", err)
	}

	// Setup the keyring and finish
	b.cache = make(map[uint32]cipher.AEAD)
	b.keyring = keyring
	return nil
}

// 生成加密环，使用rootkey来保护，如果sealkey存在，使用环上的term1号key进行加密
func (b *AESGCMBarrier) Initialize(ctx context.Context, key, sealKey []byte, reader io.Reader) error {
	min, max := b.KeyLength()
	if len(key) < min || len(key) > max {
		return fmt.Errorf("key size must be %d or %d", min, max)
	}

	if alreadyInit, err := b.Initialized(ctx); err != nil {
		return err
	} else if alreadyInit {
		return ErrBarrierAlreadyInit
	}

	encryptionKey, err := b.GenerateKey(reader)
	if err != nil {
		return fmt.Errorf("failed to generate encryption key: %w", err)
	}

	// keyring中添加一个加密key
	keyring := NewKeyring().SetRootKey(key)
	keyring, err = keyring.AddKey(&Key{
		Term:    1,
		Version: 1,
		Value:   encryptionKey,
	})
	if err != nil {
		return fmt.Errorf("failed to create keyring: %w", err)
	}

	err = b.persistKeyring(ctx, keyring)
	if err != nil {
		return err
	}

	if len(sealKey) > 0 {
		primary, err := b.aeadFromKey(encryptionKey)
		if err != nil {
			return err
		}

		// 使用keyring的1号term key来加密sealKey
		err = b.putInternal(ctx, 1, primary, &v1.Entry{
			Key:   shamirKekPath,
			Value: sealKey,
		})
		if err != nil {
			return fmt.Errorf("failed to store new seal key: %w", err)
		}
	}

	return nil
}

func (b *AESGCMBarrier) persistKeyring(ctx context.Context, keyring *Keyring) error {
	keyringBuf, err := keyring.Serialize()
	defer util.Memzero(keyringBuf)
	if err != nil {
		return fmt.Errorf("failed to serialize keyring: %w", err)
	}

	// 使用root key加密秘钥环存到core/keyring
	gcm, err := b.aeadFromKey(keyring.RootKey())
	if err != nil {
		return err
	}

	value, err := b.encrypt(keyringPath, initialKeyTerm, gcm, keyringBuf)
	if err != nil {
		return err
	}

	pe := &v1.Entry{
		Key:   keyringPath,
		Value: value,
	}
	if err := b.store.Put(ctx, pe); err != nil {
		return fmt.Errorf("failed to persist keyring: %w", err)
	}

	// 使用当前激活的keyring key加密root key存到core/master
	key := &Key{
		Term:    1,
		Version: 1,
		Value:   keyring.RootKey(),
	}
	keyBuf, err := key.Serialize()
	defer util.Memzero(keyBuf)
	if err != nil {
		return fmt.Errorf("failed to serialize root key: %w", err)
	}

	activeKey := keyring.ActiveKey()
	aead, err := b.aeadFromKey(activeKey.Value)
	if err != nil {
		return err
	}
	value, err = b.encryptTracked(rootKeyPath, activeKey.Term, aead, keyBuf)
	if err != nil {
		return err
	}

	pe = &v1.Entry{
		Key:   rootKeyPath,
		Value: value,
	}
	if err := b.store.Put(ctx, pe); err != nil {
		return fmt.Errorf("failed to persist root key: %w", err)
	}
	return nil
}

func (b *AESGCMBarrier) GenerateKey(reader io.Reader) ([]byte, error) {
	// Generate a 256bit key
	buf := make([]byte, 2*aes.BlockSize)
	_, err := reader.Read(buf)

	return buf, err
}

func (b *AESGCMBarrier) KeyLength() (int, int) {
	return aes.BlockSize, 2 * aes.BlockSize
}

// 根据term拿个对应的key，生成gcm实例
func (b *AESGCMBarrier) aeadForTerm(term uint32) (cipher.AEAD, error) {
	keyring := b.keyring
	if keyring == nil {
		return nil, nil
	}

	aead, ok := b.cache[term]
	if ok {
		return aead, nil
	}

	key := keyring.TermKey(term)
	if key == nil {
		return nil, nil
	}

	aead, err := b.aeadFromKey(key.Value)
	if err != nil {
		return nil, err
	}

	b.cache[term] = aead
	return aead, nil
}

func (b *AESGCMBarrier) aeadFromKey(key []byte) (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCM mode")
	}
	return gcm, nil
}

func (b *AESGCMBarrier) Put(ctx context.Context, entry *v1.Entry) error {
	if b.sealed {
		return ErrBarrierSealed
	}

	term := b.keyring.ActiveTerm()
	primary, err := b.aeadForTerm(term)
	if err != nil {
		return err
	}

	return b.putInternal(ctx, term, primary, entry)
}

func (b *AESGCMBarrier) putInternal(ctx context.Context, term uint32, primary cipher.AEAD, entry *v1.Entry) error {
	value, err := b.encryptTracked(entry.Key, term, primary, entry.Value)
	if err != nil {
		return err
	}
	pe := &v1.Entry{
		Key:   entry.Key,
		Value: value,
	}
	return b.store.Put(ctx, pe)
}

func (b *AESGCMBarrier) Get(ctx context.Context, key string) (*v1.Entry, error) {
	if b.sealed {
		return nil, ErrBarrierSealed
	}

	pe, err := b.store.Get(ctx, key)
	if err != nil {
		return nil, err
	} else if pe == nil {
		return nil, nil
	}

	if len(pe.Value) < 4 {
		return nil, errors.New("invalid value")
	}

	term := binary.BigEndian.Uint32(pe.Value[:4])
	gcm, err := b.aeadForTerm(term)
	if err != nil {
		return nil, err
	}
	if gcm == nil {
		return nil, fmt.Errorf("no decryption key available for term %d", term)
	}

	plain, err := b.decrypt(key, gcm, pe.Value)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	entry := &v1.Entry{
		Key:   key,
		Value: plain,
	}
	return entry, nil
}

func (b *AESGCMBarrier) Delete(ctx context.Context, key string) error {
	if b.sealed {
		return ErrBarrierSealed
	}

	return b.store.Delete(ctx, key)
}

func (b *AESGCMBarrier) List(ctx context.Context, prefix string) ([]string, error) {
	if b.sealed {
		return nil, ErrBarrierSealed
	}

	return b.store.List(ctx, prefix)
}

func (b *AESGCMBarrier) encryptTracked(key string, term uint32, gcm cipher.AEAD, value []byte) ([]byte, error) {
	ct, err := b.encrypt(key, term, gcm, value)
	if err != nil {
		return nil, err
	}
	return ct, nil
}

func (b *AESGCMBarrier) encrypt(key string, term uint32, gcm cipher.AEAD, value []byte) ([]byte, error) {
	extra := termSize + 1 + gcm.NonceSize() + gcm.Overhead()
	if len(value) > math.MaxInt-extra {
		return nil, ErrPlaintextTooLarge
	}

	capacity := len(value) + extra
	size := termSize + 1 + gcm.NonceSize()
	out := make([]byte, size, capacity)

	binary.BigEndian.PutUint32(out[:4], term)
	out[4] = b.currentAESGCMVersionByte

	nonce := out[5 : 5+gcm.NonceSize()]
	n, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	if n != len(nonce) {
		return nil, errors.New("unable to read enough random bytes to fill gcm nonce")
	}

	switch b.currentAESGCMVersionByte {
	case AESGCMVersion1:
		aad := []byte(nil)
		if key != "" {
			aad = []byte(key)
		}
		out = gcm.Seal(out, nonce, value, aad)
	default:
		panic("Unknown AESGCM version")
	}

	return out, nil
}

func (b *AESGCMBarrier) decrypt(path string, gcm cipher.AEAD, cipher []byte) ([]byte, error) {
	if len(cipher) < 5+gcm.NonceSize() {
		return nil, fmt.Errorf("invalid cipher length")
	}

	nonce := cipher[5 : 5+gcm.NonceSize()]
	raw := cipher[5+gcm.NonceSize():]
	out := make([]byte, 0, len(raw)-gcm.NonceSize())

	switch cipher[4] {
	case AESGCMVersion1:
		aad := []byte(nil)
		if path != "" {
			aad = []byte(path)
		}
		return gcm.Open(out, nonce, raw, aad)
	default:
		return nil, fmt.Errorf("version bytes mis-match")
	}
}
