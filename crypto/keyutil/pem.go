// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package keyutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

// ToDERBytes encodes the given crypto key as a byte array in ASN.1 DER Form.
// It returns the PEM block type as string, and the encoded key.
//
// A private key will be serialized using PKCS8.
// Supported private types: *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey
//
// A public key will be serialized using PKIX.
// Supported public key types: *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
func ToDERBytes(key any) (string, []byte, error) {
	// Check key
	if key == nil {
		return "", nil, errors.New("unable to encode nil key")
	}

	var (
		out []byte
		err error
	)
	switch k := key.(type) {
	// Private keys ------------------------------------------------------------
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		out, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return "", nil, fmt.Errorf("unable to serialize key: %w", err)
		}
		return "PRIVATE KEY", out, nil
	// Public keys -------------------------------------------------------------
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		out, err = x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return "", nil, fmt.Errorf("unable to serialize key: %w", err)
		}
		return "PUBLIC KEY", out, nil
	default:
	}

	return "", nil, fmt.Errorf("given key type is not supported")
}
