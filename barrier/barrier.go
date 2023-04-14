package barrier

import (
	"errors"
)

var (
	ErrBarrierSealed      = errors.New("bull is sealed")
	ErrPlaintextTooLarge  = errors.New("plaintext value too large")
	ErrBarrierAlreadyInit = errors.New("bull is already initialized")
	ErrBarrierInvalidKey  = errors.New("Unseal failed, invalid key")
	ErrBarrierNotInit     = errors.New("bull is not initialized")
)

const (
	keyringPath     = "core/keyring"
	keyringPrefix   = "core/"
	barrierInitPath = "barrier/init"
	rootKeyPath     = "core/master"
	shamirKekPath   = "core/shamir-kek"
)

type SecurityBarrier interface {
}
