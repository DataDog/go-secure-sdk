// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package d5

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// D5 provides deterministic encryption/decryption algorithm based on AES-256-GCM
// to accomplish encryption for confidentiality and authentication for integrity.
//
// To provide a deterministic behavior, the nonce value used by AES-256-GCM
// encryption is derived from the plaintext using HMAC-SHA256.
//
// This algorithm version is FIPS compliant.

const (
	minKeyLen        = 32
	nonceLen         = 12
	encryptionKeyLen = 32
	nonceKeyLen      = 32
	MagicVersion     = 0xD5
)

// -----------------------------------------------------------------------------

// Overhead returns the size overhead due to encryption.
func Overhead() int {
	// Magic (1B) || NonceLen (12B) || Tag (16B)
	return 1 + nonceLen + 16
}

// Encrypt the given plaintext with the given key using AES-256-GCM with a
// deterministic 32 bytes nonce generation based on HMAC-SHA256 of the plaintext.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	return encrypt(key, plaintext, nil)
}

// EncryptWithAdditionalData encrypts the given plaintext with the given key and
// adds the given additional data to the authentication context.
// In order to decrypt the result of this function, the same additional data
// must be provided to the `DecryptWithAdditionalData` function.
func EncryptWithAdditionalData(key, plaintext, aad []byte) ([]byte, error) {
	return encrypt(key, plaintext, aad)
}

// Decrypt the given ciphertext with the given key using AES-256-GCM.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	return decrypt(key, ciphertext, nil)
}

// DecryptWithAdditionalData decrypts the given ciphertext with the given key and
// uses the additianl data during authentication.
func DecryptWithAdditionalData(key, ciphertext, aad []byte) ([]byte, error) {
	return decrypt(key, ciphertext, aad)
}

// -----------------------------------------------------------------------------

func encrypt(key, plaintext, aad []byte) ([]byte, error) {
	// Check arguments
	if len(key) < minKeyLen {
		return nil, fmt.Errorf("key must be %d bytes long at least", minKeyLen)
	}

	// Derive encryption key (ensure sufficient entropy and don't use direct secret)
	var (
		eK [encryptionKeyLen]byte // Key
	)
	encKdf := hkdf.New(sha256.New, key, nil, []byte("datadog-convergent-encryption-key-v1"))
	if _, err := io.ReadFull(encKdf, eK[:]); err != nil {
		return nil, fmt.Errorf("unable to derive encryption key: %w", err)
	}

	// Derive deterministic nonce key (split from the given secret key)
	var nK [nonceKeyLen]byte
	nonceKdf := hkdf.New(sha256.New, key, nil, []byte("datadog-convergent-encryption-nonce-v1"))
	if _, err := io.ReadFull(nonceKdf, nK[:]); err != nil {
		return nil, fmt.Errorf("unable to derive nonce key: %w", err)
	}

	// Initialize block cipher
	b, err := aes.NewCipher(eK[:])
	if err != nil {
		return nil, fmt.Errorf("unable to initialize block cipher: %w", err)
	}

	// Compute deterministic nonce
	hm := hmac.New(sha256.New, nK[:])
	hm.Write(plaintext)
	n := hm.Sum(nil)

	// Initialize stream cipher
	s, err := cipher.NewGCMWithNonceSize(b, nonceLen)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize cipher mode: %w", err)
	}

	// Prepare final payload
	final := make([]byte, 1+nonceLen, 1+nonceLen+len(plaintext)+s.Overhead())
	final[0] = MagicVersion                                                            // Version
	copy(final[1:], n[:nonceLen])                                                      // Nonce
	final = append(final, s.Seal(final[1+nonceLen:], n[:nonceLen], plaintext, aad)...) // Ciphertext + Tag

	return final, nil
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

	// Derive encryption key.
	var (
		eK [encryptionKeyLen]byte // Key
	)
	encKdf := hkdf.New(sha256.New, key, nil, []byte("datadog-convergent-encryption-key-v1"))
	if _, err := io.ReadFull(encKdf, eK[:]); err != nil {
		return nil, fmt.Errorf("unable to derive encryption key: %w", err)
	}

	// Initialize block cipher
	b, err := aes.NewCipher(eK[:])
	if err != nil {
		return nil, fmt.Errorf("unable to initialize block cipher: %w", err)
	}

	// Initialize stream cipher
	s, err := cipher.NewGCM(b)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize cipher mode: %w", err)
	}

	// Open sealed content
	plaintext, err := s.Open(nil, ciphertext[1:1+nonceLen], ciphertext[1+nonceLen:], aad)
	if err != nil {
		return nil, fmt.Errorf("unable to open sealed content: %w", err)
	}

	return plaintext, nil
}
