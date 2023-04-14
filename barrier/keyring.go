package barrier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	utils "github.com/zilicorp/bull/pkg/utils"
)

// for serialization
type EncodedKeyring struct {
	MasterKey []byte
	Keys      []*Key
}

type Key struct {
	Term        uint32
	Version     int
	Value       []byte
	InstallTime time.Time
	Encryptions uint64 `json:"encryptions,omitempty"`
}

func (k *Key) Serialize() ([]byte, error) {
	return json.Marshal(k)
}

type Keyring struct {
	rootKey    []byte
	keys       map[uint32]*Key
	activeTerm uint32
}

func NewKeyring() *Keyring {
	return &Keyring{
		keys:       make(map[uint32]*Key),
		activeTerm: 0,
	}
}

func (k *Keyring) Zeroize(keysToo bool) {
	if k == nil {
		return
	}
	if k.rootKey != nil {
		utils.Memzero(k.rootKey)
	}
	if !keysToo || k.keys == nil {
		return
	}
	for _, key := range k.keys {
		utils.Memzero(key.Value)
	}
}

func (k *Keyring) SetRootKey(val []byte) *Keyring {
	valCopy := make([]byte, len(val))
	copy(valCopy, val)
	clone := k.Clone()
	clone.rootKey = valCopy
	return clone
}

func (k *Keyring) Clone() *Keyring {
	clone := &Keyring{
		rootKey:    k.rootKey,
		keys:       make(map[uint32]*Key, len(k.keys)),
		activeTerm: k.activeTerm,
	}
	for idx, key := range k.keys {
		clone.keys[idx] = key
	}
	return clone
}

func (k *Keyring) AddKey(key *Key) (*Keyring, error) {
	// 不允许对已存在的term值进行替换
	if exist, ok := k.keys[key.Term]; ok {
		if !bytes.Equal(key.Value, exist.Value) {
			return nil, fmt.Errorf("conflicting key for term %d already installed", key.Term)
		}
		return k, nil
	}
	if key.InstallTime.IsZero() {
		key.InstallTime = time.Now()
	}
	clone := k.Clone()
	clone.keys[key.Term] = key

	// 只会激活更大term的key
	if key.Term > clone.activeTerm {
		clone.activeTerm = key.Term
	}

	// 清除历史term加密的次数统计
	for term, key := range clone.keys {
		if term != clone.activeTerm {
			key.Encryptions = 0
		}
	}

	return clone, nil
}

func (k *Keyring) RootKey() []byte {
	return k.rootKey
}

func (k *Keyring) ActiveKey() *Key {
	return k.keys[k.activeTerm]
}

func (k *Keyring) Serialize() ([]byte, error) {
	// Create the encoded entry
	enc := EncodedKeyring{
		MasterKey: k.rootKey,
	}
	for _, key := range k.keys {
		enc.Keys = append(enc.Keys, key)
	}

	// JSON encode the keyring
	buf, err := json.Marshal(enc)
	return buf, err
}

func (k *Keyring) ActiveTerm() uint32 {
	return k.activeTerm
}

func (k *Keyring) TermKey(term uint32) *Key {
	return k.keys[term]
}

func DeserializeKeyring(buf []byte) (*Keyring, error) {
	// Deserialize the keyring
	var enc EncodedKeyring
	if err := utils.DecodeJSON(buf, &enc); err != nil {
		return nil, fmt.Errorf("deserialization failed: %w", err)
	}

	// Create a new keyring
	k := NewKeyring()
	k.rootKey = enc.MasterKey
	for _, key := range enc.Keys {
		k.keys[key.Term] = key
		if key.Term > k.activeTerm {
			k.activeTerm = key.Term
		}
	}
	return k, nil
}
