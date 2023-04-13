package barrier

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	v1 "github.com/zilicorp/bull/api/core/v1"
	"github.com/zilicorp/bull/store"
)

var (
	ErrBarrierSealed     = errors.New("bull is sealed")
	ErrPlaintextTooLarge = errors.New("plaintext value too large")
)

const (
	AESGCMVersion1 = 0x1
)

type AESGCMBarrier struct {
	store   store.Store
	sealed  bool
	keyring *Keyring

	cache map[uint32]cipher.AEAD

	currentAESGCMVersionByte byte
}

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

func (b *AESGCMBarrier) encryptTracked(key string, term uint32, gcm cipher.AEAD, value []byte) ([]byte, error) {
	ct, err := b.encrypt(key, term, gcm, value)
	if err != nil {
		return nil, err
	}
	return ct, nil
}

const termSize = 4

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
