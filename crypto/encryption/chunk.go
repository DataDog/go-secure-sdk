// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package encryption

import (
	"errors"
	"fmt"
	"io"

	"github.com/DataDog/go-secure-sdk/crypto/canonicalization"
	"github.com/DataDog/go-secure-sdk/crypto/encryption/internal/d3"
	"github.com/DataDog/go-secure-sdk/crypto/encryption/internal/d4"
)

// Chunked represents a chunked stream encryption. It should be used for large
// stream encryption.
func Chunked(key []byte) (ChunkedAEAD, error) {
	// Using FIPS by default here, because it looks like go runtime has hardware
	// acceleration for the cipher suite used.
	return ChunkedWithMode(FIPS, key)
}

// ChunkedWithMode represents value byte array encryption.
func ChunkedWithMode(mode Mode, key []byte) (ChunkedAEAD, error) {
	// Ensure too large key to prevent a too large allocation
	if len(key) > maximumKeyLength {
		return nil, fmt.Errorf("the provided key is too large, ensure a key smaller than %d bytes", maximumKeyLength)
	}

	// Copy the key for resiliency reasons
	keyRaw := make([]byte, len(key))
	copy(keyRaw, key)

	// Select the appropriate mode
	switch mode {
	case FIPS:
		return &chunkedAEAD{
			key:         keyRaw,
			encryptFunc: d3.EncryptWithAdditionalData,
			decryptFunc: d3.DecryptWithAdditionalData,
		}, nil
	case Modern:
		return &chunkedAEAD{
			key:         keyRaw,
			encryptFunc: d4.EncryptWithAdditionalData,
			decryptFunc: d4.DecryptWithAdditionalData,
		}, nil
	default:
	}

	return nil, errors.New("unsupported cipher suite")
}

// -----------------------------------------------------------------------------

type chunkedAEAD struct {
	key         []byte
	encryptFunc func(dst io.Writer, plaintext io.Reader, key, aad []byte) error
	decryptFunc func(dst io.Writer, ciphertext io.Reader, key, aad []byte) error
}

// Seal the given plaintext.
func (ce *chunkedAEAD) Seal(dst io.Writer, plaintext io.Reader) error {
	return ce.encryptFunc(dst, plaintext, ce.key, nil)
}

// SealWithContext encrypts the given plaintext and inject all given
// additional data for authentication purpose.
func (ce *chunkedAEAD) SealWithContext(dst io.Writer, plaintext io.Reader, context ...[]byte) error {
	// Prepare AAD
	aad, err := canonicalization.PreAuthenticationEncoding(context...)
	if err != nil {
		return fmt.Errorf("unable to prepare context: %w", err)
	}

	return ce.encryptFunc(dst, plaintext, ce.key, aad)
}

// Decrypt the given ciphertext.
func (ce *chunkedAEAD) Open(dst io.Writer, ciphertext io.Reader) error {
	return ce.decryptFunc(dst, ciphertext, ce.key, nil)
}

// OpenWithContext decrypts the given ciphertext and inject all given context
// information for authentication purpose. The context value must be exactly
// the same used for encryption.
func (ce *chunkedAEAD) OpenWithContext(dst io.Writer, ciphertext io.Reader, context ...[]byte) error {
	// Prepare AAD
	aad, err := canonicalization.PreAuthenticationEncoding(context...)
	if err != nil {
		return fmt.Errorf("unable to prepare context: %w", err)
	}

	return ce.decryptFunc(dst, ciphertext, ce.key, aad)
}
