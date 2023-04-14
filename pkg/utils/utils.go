package utils

import (
	"crypto/rand"
	"fmt"
)

func Memzero(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

func Randbytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("failed to generate %d random bytes: %v", n, err))
	}
	return buf
}
