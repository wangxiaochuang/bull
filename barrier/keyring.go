package barrier

import "time"

type Key struct {
	Term        uint32
	Version     int
	Value       []byte
	InstallTime time.Time
	Encryptions uint64 `json:"encryptions,omitempty"`
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

func (k *Keyring) ActiveTerm() uint32 {
	return k.activeTerm
}

func (k *Keyring) TermKey(term uint32) *Key {
	return k.keys[term]
}
