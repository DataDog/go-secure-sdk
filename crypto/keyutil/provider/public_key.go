// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"crypto"
	"errors"

	"gopkg.in/square/go-jose.v2"

	"github.com/DataDog/go-secure-sdk/crypto/signature"
)

const (
	jwkSignaturePurpose  = "sig"
	jwkEncryptionPurpose = "enc"
)

var _ PublicKey = (*defaultPublicKey)(nil)

type defaultPublicKey struct {
	alias    KeyAlias
	key      crypto.PublicKey
	purposes KeyPurposes
}

func (pub *defaultPublicKey) Can(purpose KeyPurpose) bool {
	return pub.purposes.Can(purpose)
}

func (pub *defaultPublicKey) Alias() KeyAlias {
	return pub.alias
}

// Public returns the public key.
func (pub *defaultPublicKey) Public() crypto.PublicKey {
	return pub.key
}

// AsBytes exports the public key using PKIX ASN.1 encoding.
func (pub *defaultPublicKey) AsBytes() ([]byte, error) {
	return asBytes(pub.key)
}

// AsPEM returns the public key encoded with PKIX PEM.
func (pub *defaultPublicKey) AsPEM() (string, error) {
	return asPEM(pub.key)
}

// AsJWK returns the public key encoded as a JSON Web Key.
func (pub *defaultPublicKey) AsJWK() (string, error) {
	// Create the JWK instance
	k := &jose.JSONWebKey{
		Key: pub.key,
	}

	// Assign key usage
	switch {
	case pub.Can(EncryptionPurpose):
		k.Use = jwkEncryptionPurpose
	case pub.Can(SignaturePurpose):
		k.Use = jwkSignaturePurpose
	default:
	}

	// Encode JWK as JSON
	return asJSON(k)
}

// Verifier returns a verifier created from the public key.
func (pub *defaultPublicKey) Verifier() (signature.Verifier, error) {
	if !pub.Can(SignaturePurpose) || pub.Can(EncryptionPurpose) {
		return nil, errors.New("this key is not useable for signature")
	}

	//nolint:wrapcheck
	return signature.FromPublicKey(pub.key)
}
