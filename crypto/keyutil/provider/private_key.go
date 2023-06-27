// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"crypto"
	"errors"

	"gopkg.in/square/go-jose.v2"

	"github.com/DataDog/go-secure-sdk/crypto/signature"
)

var _ PrivateKey = (*defaultPrivateKey)(nil)

type defaultPrivateKey struct {
	alias    KeyAlias
	key      crypto.Signer
	purposes KeyPurposes
}

func (priv *defaultPrivateKey) Can(purpose KeyPurpose) bool {
	return priv.purposes.Can(purpose)
}

func (priv *defaultPrivateKey) Alias() KeyAlias {
	return priv.alias
}

// Public returns the public key.
func (priv *defaultPrivateKey) Public() crypto.PublicKey {
	return priv.key.Public()
}

// AsBytes exports the private key using PKIX ASN.1 encoding.
func (priv *defaultPrivateKey) AsBytes() ([]byte, error) {
	if !priv.Can(ExportableKey) {
		return nil, errors.New("this key is not exportable")
	}

	return asBytes(priv.key)
}

// AsPEM returns the private key encoded with PKIX PEM.
func (priv *defaultPrivateKey) AsPEM() (string, error) {
	if !priv.Can(ExportableKey) {
		return "", errors.New("this key is not exportable")
	}

	return asPEM(priv.key)
}

// AsJWK returns the private key encoded as a JSON Web Key.
func (priv *defaultPrivateKey) AsJWK() (string, error) {
	if !priv.Can(ExportableKey) {
		return "", errors.New("this key is not exportable")
	}

	// Create the JWK instance
	k := &jose.JSONWebKey{
		Key: priv.key,
	}

	// Assign key usage
	switch {
	case priv.Can(EncryptionPurpose):
		k.Use = jwkEncryptionPurpose
	case priv.Can(SignaturePurpose):
		k.Use = jwkSignaturePurpose
	default:
	}

	return asJSON(k)
}

// Verifier returns a verifier created from the public key.
func (priv *defaultPrivateKey) Signer() (signature.Signer, error) {
	if !priv.Can(SignaturePurpose) {
		return nil, errors.New("this key is not useable for signature")
	}
	if priv.Can(EncryptionPurpose) {
		return nil, errors.New("this key is useable for encryption hence signature operations are disabled")
	}

	//nolint:wrapcheck
	return signature.FromPrivateKey(priv.key)
}
