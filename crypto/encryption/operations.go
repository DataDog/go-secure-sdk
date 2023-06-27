// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package encryption

import (
	"errors"
	"fmt"

	"github.com/DataDog/go-secure-sdk/crypto/canonicalization"
	"github.com/DataDog/go-secure-sdk/crypto/encryption/internal/d1"
	"github.com/DataDog/go-secure-sdk/crypto/encryption/internal/d2"
	"github.com/DataDog/go-secure-sdk/crypto/encryption/internal/d5"
)

// ErrNoMatchingKey is raised when the operation can't be successful with
// any given keys.
var ErrNoMatchingKey = errors.New("no matching key")

// Open a sealed content using multiple keys.
// Returns the plaintext if one key match else it returns ErrNoMatchingKey.
func Open(keys [][]byte, ciphertext []byte, context ...[]byte) ([]byte, error) {
	// Check arguments
	if len(keys) == 0 {
		return nil, errors.New("no keys provided")
	}
	if len(ciphertext) < 1 {
		return nil, errors.New("ciphertext too short")
	}

	// Prepare AAD
	aad, err := canonicalization.PreAuthenticationEncoding(context...)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare context: %w", err)
	}

	// Retrieve version magic
	version := ciphertext[0]

LOOP:
	for _, k := range keys {
		var (
			plaintext []byte
			err       error
		)
		switch version {
		case d1.MagicVersion:
			plaintext, err = d1.DecryptWithAdditionalData(k, ciphertext, aad)
		case d2.MagicVersion:
			plaintext, err = d2.DecryptWithAdditionalData(k, ciphertext, aad)
		case d5.MagicVersion:
			plaintext, err = d5.DecryptWithAdditionalData(k, ciphertext, aad)
		default:
			break LOOP
		}
		if err != nil {
			continue // Try next key
		}

		return plaintext, nil
	}

	return nil, ErrNoMatchingKey
}

// RotateKey rotates encryption key used by trying to decrypt the given ciphertext
// with a given key set as old keys, and try to re-encrypt the data using the new key.
func RotateKey(oldkeys [][]byte, newkey, ciphertext []byte, context ...[]byte) (newciphertext []byte, err error) {
	// Try to open the sealed content
	plaintext, err := Open(oldkeys, ciphertext, context...)
	if err != nil {
		return nil, fmt.Errorf("unable to rotate encryption key, decryption failed: %w", err)
	}

	// Prepare AAD
	aad, err := canonicalization.PreAuthenticationEncoding(context...)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare context: %w", err)
	}

	// Retrieve version magic
	version := ciphertext[0]

	switch version {
	case d1.MagicVersion:
		newciphertext, err = d1.EncryptWithAdditionalData(newkey, plaintext, aad)
	case d2.MagicVersion:
		newciphertext, err = d2.EncryptWithAdditionalData(newkey, plaintext, aad)
	case d5.MagicVersion:
		newciphertext, err = d5.EncryptWithAdditionalData(newkey, plaintext, aad)
	default:
		return nil, fmt.Errorf("unsuppored encryption algorithm version: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to rotate encryption key, encryption failed: %w", err)
	}

	return newciphertext, err
}
