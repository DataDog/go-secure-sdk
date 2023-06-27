// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package keyutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"

	security "github.com/DataDog/go-secure-sdk"
)

// IsUsable returns an error if the given key as environmental restrictions.
func IsUsable(key any) error {
	// Extract crypto key
	k, err := ExtractKey(key)
	if err != nil {
		return fmt.Errorf("unable to extract a key from the given object: %w", err)
	}

	switch k.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, *rsa.PublicKey, *ecdsa.PublicKey:
		// Accept in any case
		return nil
	case ed25519.PrivateKey, ed25519.PublicKey:
		if security.InFIPSMode() {
			return errors.New("Ed25519 keys are not useable in FIPS mode")
		}
		return nil
	default:
	}

	return fmt.Errorf("unable to decide for unknown key type %T", key)
}
