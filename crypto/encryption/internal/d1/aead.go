// Package d1 provides FIPS compliant value encryption system
package d1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// D1 provides encryption/decryption algorithm based on AES-256+HMAC-SHA256 to
// accomplish encryption for confidentiality and authentication for integrity.
//
// The key leak risks are reduced due to the fact that each operation has its
// own derived keys for encryption and authentication.
//
// This algorithm version is FIPS compliant.

const (
	minKeyLen            = 32
	nonceLen             = 24
	encryptionKeyLen     = 32
	authenticationKeyLen = 32
	MagicVersion         = 0xD1
)

// -----------------------------------------------------------------------------

// Overhead returns the size overhead due to encryption.
func Overhead() int {
	return 1 + nonceLen + sha256.Size
}

// Encrypt the given plaintext with the given key using AES-256-CTR+HMAC-SHA256.
// The keys are derived using HKDF-SHA256 to ensure a sufficient entropy for
// the encryption and the authentication.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	return encrypt(rand.Reader, key, plaintext, nil)
}

// EncryptWithAdditionalData encrypts the given plaintext with the given key and
// adds the given additional data to the authentication context.
// In order to decrypt the result of this function, the same additional data
// must be provided to the `DecryptWithAdditionalData` function.
func EncryptWithAdditionalData(key, plaintext, aad []byte) ([]byte, error) {
	return encrypt(rand.Reader, key, plaintext, aad)
}

// Decrypt the given ciphertext with the given key using AES-CTR+HMAC-SHA256.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	return decrypt(key, ciphertext, nil)
}

// DecryptWithAdditionalData decrypts the given ciphertext with the given key and
// uses the additianl data during authentication.
func DecryptWithAdditionalData(key, ciphertext, aad []byte) ([]byte, error) {
	return decrypt(key, ciphertext, aad)
}

// -----------------------------------------------------------------------------

func encrypt(r io.Reader, key, plaintext, aad []byte) ([]byte, error) {
	// Check arguments
	if len(key) < minKeyLen {
		return nil, errors.New("key must be 32 bytes long at least")
	}

	// Generate rand nonce
	var n [nonceLen]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, fmt.Errorf("unable to generate random nonce: %w", err)
	}

	// Derive encryption key and iv to ensure a sufficient entropy.
	var (
		eK [encryptionKeyLen + aes.BlockSize]byte // Key + IV
	)
	encKdf := hkdf.New(sha256.New, key, n[:], []byte("datadog-encryption-key-v1"))
	if _, err := io.ReadFull(encKdf, eK[:]); err != nil {
		return nil, fmt.Errorf("unable to derive encryption key: %w", err)
	}

	// Derive authentication key to ensure a sufficient entropy
	var aK [authenticationKeyLen]byte
	authKdf := hkdf.New(sha256.New, key, n[:], []byte("datadog-authentication-key-v1"))
	if _, err := io.ReadFull(authKdf, aK[:]); err != nil {
		return nil, fmt.Errorf("unable to derive authentication key: %w", err)
	}

	// Initialize block cipher
	b, err := aes.NewCipher(eK[:encryptionKeyLen])
	if err != nil {
		return nil, fmt.Errorf("unable to initialize block cipher: %w", err)
	}

	// Initialize stream cipher
	s := cipher.NewCTR(b, eK[encryptionKeyLen:])

	// Prepare final payload
	final := make([]byte, 1+nonceLen+len(plaintext), 1+nonceLen+len(plaintext)+sha256.Size)
	final[0] = MagicVersion                       // Version
	copy(final[1:], n[:])                         // Nonce
	s.XORKeyStream(final[1+nonceLen:], plaintext) // Ciphertext

	// Prepare HMAC-SHA256
	h := hmac.New(sha256.New, aK[:])
	h.Write(final)
	h.Write(aad)

	return h.Sum(final), nil
}

func decrypt(key, ciphertext, aad []byte) ([]byte, error) {
	// Check arguments
	if len(key) < minKeyLen {
		return nil, errors.New("key must be 32 bytes long at least")
	}
	if len(ciphertext) < Overhead() {
		return nil, errors.New("ciphertext is too short")
	}

	// Ensure supported version
	if ciphertext[0] != MagicVersion {
		return nil, errors.New("invalid ciphertext magic")
	}

	// Derive encryption key
	var (
		eK [encryptionKeyLen + aes.BlockSize]byte // Key + IV
	)
	encKdf := hkdf.New(sha256.New, key, ciphertext[1:1+nonceLen], []byte("datadog-encryption-key-v1"))
	if _, err := io.ReadFull(encKdf, eK[:]); err != nil {
		return nil, fmt.Errorf("unable to derive encryption key: %w", err)
	}

	// Derive authentication key
	var aK [authenticationKeyLen]byte
	authKdf := hkdf.New(sha256.New, key, ciphertext[1:1+nonceLen], []byte("datadog-authentication-key-v1"))
	if _, err := io.ReadFull(authKdf, aK[:]); err != nil {
		return nil, fmt.Errorf("unable to derive authentication key: %w", err)
	}

	// Prepare HMAC-SHA256
	h := hmac.New(sha256.New, aK[:])
	h.Write(ciphertext[:len(ciphertext)-sha256.Size])
	h.Write(aad)

	// Compare tag
	if subtle.ConstantTimeCompare(h.Sum(nil), ciphertext[len(ciphertext)-sha256.Size:]) != 1 {
		return nil, errors.New("unable to authenticate decryption attempt")
	}

	// Initialize block cipher
	b, err := aes.NewCipher(eK[:encryptionKeyLen])
	if err != nil {
		return nil, fmt.Errorf("unable to initialize block cipher: %w", err)
	}

	// Initialize stream cipher
	s := cipher.NewCTR(b, eK[encryptionKeyLen:])

	// In-place decrypt
	s.XORKeyStream(ciphertext[1+nonceLen:len(ciphertext)-sha256.Size], ciphertext[1+nonceLen:len(ciphertext)-sha256.Size])

	return ciphertext[1+nonceLen : len(ciphertext)-sha256.Size], nil
}
