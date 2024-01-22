package value

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"sync"

	"github.com/awnumar/memguard"

	"github.com/DataDog/go-secure-sdk/crypto/encryption"
	"github.com/DataDog/go-secure-sdk/value/transformer"
)

var (
	// Generate random initial encryption key
	encryptionKeyMutex sync.RWMutex
	encryptionKey      = memguard.NewEnclaveRandom(32)

	// Generate random initial tokenization key
	tokenizationKeyMutex sync.Mutex
	tokenizationKey      = memguard.NewEnclaveRandom(32)
)

// AsToken returns a wrapped types which will hash its value when trying to
// access its value for printing/serializing purpose.
//
// Tokens are not deserializable.
func AsToken[T any](v T) Wrapped[T] {
	return AsWrapped(v, transformer.Hash(func() hash.Hash {
		// Open enclave
		key, err := tokenizationKey.Open()
		if err != nil {
			panic(fmt.Errorf("unable to open tokenization key enclave: %w", err))
		}
		defer key.Destroy()

		return hmac.New(sha256.New, key.Bytes())
	}))
}

// AsEncrypted returns a wrapped value which will encrypt its value when trying
// to access its value for printing/serializing purpose.
//
// Encrypted values are deserializable.
func AsEncrypted[T any](v T) Wrapped[T] {
	// Open enclave
	key, err := encryptionKey.Open()
	if err != nil {
		panic(fmt.Errorf("unable to open encryption key enclave: %w", err))
	}
	defer key.Destroy()

	// Initialize value encryption
	aead, err := encryption.Value(key.Bytes())
	if err != nil {
		panic(fmt.Errorf("unable to initialize value encryption: %w", err))
	}

	return AsWrapped(v, transformer.Encryption(aead))
}

// -----------------------------------------------------------------------------

// SetDefaultEncryptionKey sets the encryption key used for default value encryption.
func SetDefaultEncryptionKey(key []byte) error {
	// Ensure key minimal length
	if len(key) < 32 {
		return errors.New("the given key is too short, expecting at least 32 bytes")
	}

	// Copy to local
	encryptionKeyMutex.Lock()
	encryptionKey = memguard.NewEnclave(key)
	encryptionKeyMutex.Unlock()
	memguard.WipeBytes(key)

	return nil
}

// SetDefaultTokenizationKey sets the HMAC-SHA256 key used for default tokenization.
func SetDefaultTokenizationKey(key []byte) error {
	// Ensure key minimal length
	if len(key) < 32 {
		return errors.New("the given key is too short, expecting at least 32 bytes")
	}

	// Copy to local
	tokenizationKeyMutex.Lock()
	tokenizationKey = memguard.NewEnclave(key)
	tokenizationKeyMutex.Unlock()
	memguard.WipeBytes(key)

	return nil
}
