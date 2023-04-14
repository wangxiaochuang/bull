package v1

import (
	"encoding/hex"
	"fmt"
)

type Entry struct {
	Key   string
	Value []byte
}

func (e *Entry) String() string {
	return fmt.Sprintf("key: %s. Value: %s", e.Key, hex.EncodeToString(e.Value))
}
