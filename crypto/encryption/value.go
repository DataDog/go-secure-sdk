package encryption

import (
	"errors"
	"fmt"

	security "github.com/DataDog/go-secure-sdk"
	"github.com/DataDog/go-secure-sdk/crypto/canonicalization"
	"github.com/DataDog/go-secure-sdk/crypto/encryption/internal/d1"
	"github.com/DataDog/go-secure-sdk/crypto/encryption/internal/d2"
)

// Value represents a finite byte array encryption. It should be used to small
// content encryption to prevent excessive memory consumption.
func Value(key []byte) (ValueAEAD, error) {
	// If FIPS compliance is enabled use FIPS compliant cipher suite.
	if security.InFIPSMode() {
		return ValueWithMode(FIPS, key)
	}
	return ValueWithMode(Modern, key)
}

// ValueWithMode represents value byte array encryption.
func ValueWithMode(mode Mode, key []byte) (ValueAEAD, error) {
	// Ensure too large key to prevent a too large allocation
	if len(key) > maximumKeyLength {
		return nil, fmt.Errorf("the provided key is too large, ensure a key smaller than %d bytes", maximumKeyLength)
	}

	// Copy the key for resiliency reasons
	keyRaw := make([]byte, len(key))
	copy(keyRaw, key)

	// Select appropriate mode
	switch mode {
	case FIPS:
		return &valueAEAD{
			cipherID:    d1.MagicVersion,
			key:         keyRaw,
			encryptFunc: d1.EncryptWithAdditionalData,
			decryptFunc: d1.DecryptWithAdditionalData,
		}, nil
	case Modern:
		// If FIPS compliance is enabled use FIPS compliant cipher suite.
		if security.InFIPSMode() {
			return nil, errors.New("Modern cipher is disabled in FIPS mode")
		}

		return &valueAEAD{
			cipherID:    d2.MagicVersion,
			key:         keyRaw,
			encryptFunc: d2.EncryptWithAdditionalData,
			decryptFunc: d2.DecryptWithAdditionalData,
		}, nil
	default:
	}

	return nil, errors.New("unsupported cipher suite")
}

// -----------------------------------------------------------------------------

type valueAEAD struct {
	cipherID    uint8
	key         []byte
	encryptFunc func(key, plaintext, aad []byte) ([]byte, error)
	decryptFunc func(key, ciphertext, aad []byte) ([]byte, error)
}

// CipherID returns the cipher suite identifier.
func (fe *valueAEAD) CipherID() uint8 { return fe.cipherID }

// Seal the given plaintext.
func (fe *valueAEAD) Seal(plaintext []byte) ([]byte, error) {
	return fe.encryptFunc(fe.key, plaintext, nil)
}

// EncryptWithAdditionnalData encrypts the given plaintext and inject all given
// additional data for authentication purpose.
func (fe *valueAEAD) SealWithContext(plaintext []byte, context ...[]byte) ([]byte, error) {
	// Prepare AAD
	aad, err := canonicalization.PreAuthenticationEncoding(context...)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare context: %w", err)
	}

	return fe.encryptFunc(fe.key, plaintext, aad)
}

// Decrypt the given ciphertext.
func (fe *valueAEAD) Open(ciphertext []byte) ([]byte, error) {
	return fe.decryptFunc(fe.key, ciphertext, nil)
}

// DecryptWithContext decrypts the given ciphertext and inject all given context
// information for authentication purpose. The context value must be exactly
// the same used for encryption.
func (fe *valueAEAD) OpenWithContext(ciphertext []byte, context ...[]byte) ([]byte, error) {
	// Prepare AAD
	aad, err := canonicalization.PreAuthenticationEncoding(context...)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare context: %w", err)
	}

	return fe.decryptFunc(fe.key, ciphertext, aad)
}
