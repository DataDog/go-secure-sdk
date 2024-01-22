package password

import (
	"crypto/rand"
	"io"
)

// FixedNonce returns a nonce factory that returns the given salt
func FixedNonce(salt []byte) func() []byte {
	return func() []byte {
		return salt
	}
}

// RandomNonce returns a nonce factory that returns a random length bound salt
func RandomNonce(length int) func() []byte {
	return func() []byte {
		salt := make([]byte, length)
		if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
			panic(err)
		}
		return salt
	}
}
