// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package transformer

import (
	"fmt"

	"github.com/DataDog/go-secure-sdk/crypto/encryption"
)

// Encryption initializes an encryption value transformer.
func Encryption(aead encryption.ValueAEAD) Transformer {
	return &encryptionTransformer{
		aead: aead,
	}
}

// -----------------------------------------------------------------------------
type encryptionTransformer struct {
	aead encryption.ValueAEAD
}

func (t *encryptionTransformer) Encode(plaintext []byte) ([]byte, error) {
	// Seal the input
	ciphertext, err := t.aead.Seal(plaintext)
	if err != nil {
		return nil, fmt.Errorf("unable to apply value transformation: %w", err)
	}

	return ciphertext, nil
}

func (t *encryptionTransformer) Decode(ciphertext []byte) ([]byte, error) {
	// Decrypt the ciphertext
	plaintext, err := t.aead.Open(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("unable to revert value transformation: %w", err)
	}

	return plaintext, nil
}
