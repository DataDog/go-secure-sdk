package encryption

import (
	"fmt"

	"github.com/DataDog/go-secure-sdk/crypto/encryption/internal/d5"
)

// Convergent initializes a finite value encryption using deterministic
// encryption system.
func Convergent(key []byte) (ValueAEAD, error) {
	// Ensure too large key to prevent a too large allocation
	if len(key) > maximumKeyLength {
		return nil, fmt.Errorf("the provided key is too large, ensure a key smaller than %d bytes", maximumKeyLength)
	}

	// Copy the key for resiliency reasons
	keyRaw := make([]byte, len(key))
	copy(keyRaw, key)

	return &valueAEAD{
		cipherID:    d5.MagicVersion,
		key:         keyRaw,
		encryptFunc: d5.EncryptWithAdditionalData,
		decryptFunc: d5.DecryptWithAdditionalData,
	}, nil
}
