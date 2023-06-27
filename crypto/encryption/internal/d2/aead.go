// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package d2 provides Modern value encryption system
package d2

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

// D2 provides encryption/decryption algorithm based on CHACHA20+KEYED-BLAKE2B to
// accomplish encryption for confidentiality and authentication for integrity.
//
// The key leak risks are reduced due to the fact that each operation has its
// own derived keys for encryption and authentication.
//
// This algorithm version is NOT FIPS compliant.

const (
	minKeyLen            = 32
	nonceLen             = 24
	encryptionKeyLen     = 32
	encryptionNonceLen   = 12
	authenticationKeyLen = 32
	tagLen               = 32
	MagicVersion         = 0xD2
)

// -----------------------------------------------------------------------------

// Overhead returns the size overhead due to encryption.
func Overhead() int {
	return 1 + nonceLen + tagLen
}

// Encrypt the given plaintext with the given key using CHACHA20+KEYED-BLAKE2B.
// The keys are derived using Blake2bXOF to ensure a sufficient entropy for
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

// Decrypt the given ciphertext with the given key using CHACHA20+KEYED-BLAKE2B.
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
		eK [encryptionKeyLen + encryptionNonceLen]byte // Key + IV
	)
	encKdf, err := blake2b.NewXOF(uint32(len(eK)), key)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize encryption key kdf: %w", err)
	}

	//nolint:errcheck // Don't return error by design
	encKdf.Write([]byte("datadog-encryption-key-v2"))
	//nolint:errcheck // Don't return error by design
	encKdf.Write(n[:])

	if _, err := io.ReadFull(encKdf, eK[:]); err != nil {
		return nil, fmt.Errorf("unable to derive encryption key: %w", err)
	}

	// Derive authentication key to ensure a sufficient entropy
	var aK [authenticationKeyLen]byte
	authKdf, err := blake2b.NewXOF(uint32(len(aK)), key)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize authentication key kdf: %w", err)
	}

	//nolint:errcheck // Doesn't return error by design
	authKdf.Write([]byte("datadog-authentication-key-v2"))
	//nolint:errcheck // Doesn't return error by design
	authKdf.Write(n[:])

	if _, err := io.ReadFull(authKdf, aK[:]); err != nil {
		return nil, fmt.Errorf("unable to derive authentication key: %w", err)
	}

	// Initialize stream cipher
	s, err := chacha20.NewUnauthenticatedCipher(eK[:encryptionKeyLen], eK[encryptionKeyLen:])
	if err != nil {
		return nil, fmt.Errorf("unable to initialize stream cipher: %w", err)
	}

	// Prepare final payload
	final := make([]byte, 1+nonceLen+len(plaintext), 1+nonceLen+len(plaintext)+tagLen)
	final[0] = MagicVersion                       // Version
	copy(final[1:], n[:])                         // Nonce
	s.XORKeyStream(final[1+nonceLen:], plaintext) // Ciphertext

	// Prepare Blake2b-256
	h, err := blake2b.New256(aK[:])
	if err != nil {
		return nil, fmt.Errorf("unable to initialize authentication hasher: %w", err)
	}

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

	// Derive encryption and authentication keys
	var (
		eK [encryptionKeyLen + encryptionNonceLen]byte // Key + IV
	)
	encKdf, err := blake2b.NewXOF(uint32(len(eK)), key)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize encryption key kdf: %w", err)
	}

	//nolint:errcheck // Doesn't return error by design
	encKdf.Write([]byte("datadog-encryption-key-v2"))
	//nolint:errcheck // Doesn't return error by design
	encKdf.Write(ciphertext[1 : 1+nonceLen])

	if _, err := io.ReadFull(encKdf, eK[:]); err != nil {
		return nil, fmt.Errorf("unable to derive encryption key: %w", err)
	}

	// Derive authentication key to ensure a sufficient entropy
	var aK [authenticationKeyLen]byte
	authKdf, err := blake2b.NewXOF(uint32(len(aK)), key)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize authentication key kdf: %w", err)
	}

	//nolint:errcheck
	authKdf.Write([]byte("datadog-authentication-key-v2"))
	//nolint:errcheck
	authKdf.Write(ciphertext[1 : 1+nonceLen])

	if _, err := io.ReadFull(authKdf, aK[:]); err != nil {
		return nil, fmt.Errorf("unable to derive authentication key: %w", err)
	}

	// Prepare Blake2b-256
	h, err := blake2b.New256(aK[:])
	if err != nil {
		return nil, fmt.Errorf("unable to initialize authentication hasher: %w", err)
	}

	h.Write(ciphertext[:len(ciphertext)-tagLen])
	h.Write(aad)

	// Compare tag
	if subtle.ConstantTimeCompare(h.Sum(nil), ciphertext[len(ciphertext)-tagLen:]) != 1 {
		return nil, errors.New("unable to authenticate decryption attempt")
	}

	// Initialize stream cipher
	s, err := chacha20.NewUnauthenticatedCipher(eK[:encryptionKeyLen], eK[encryptionKeyLen:])
	if err != nil {
		return nil, fmt.Errorf("unable to initialize stream cipher: %w", err)
	}

	// In-place decrypt
	s.XORKeyStream(ciphertext[1+nonceLen:len(ciphertext)-tagLen], ciphertext[1+nonceLen:len(ciphertext)-tagLen])

	return ciphertext[1+nonceLen : len(ciphertext)-tagLen], nil
}
