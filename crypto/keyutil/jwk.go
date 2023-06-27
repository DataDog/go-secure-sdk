// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package keyutil

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"gopkg.in/square/go-jose.v2"
)

const (
	maxJWKLength = 1 << 20 // 1MB
)

// ToJWK encodes the given key as JWK.
func ToJWK(key any) (*jose.JSONWebKey, error) {
	// Check key
	if key == nil {
		return nil, errors.New("unable to pack nil key")
	}

	// Prepare JWK object
	jwk := jose.JSONWebKey{
		Key: key,
	}

	// Use the public key
	kid, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("unable to compute key thumbprint: %w", err)
	}

	// Assign thumbprint as key identifier
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(kid)

	return &jwk, nil
}

// ToEncryptedJWK wraps the JWK encoded in a JWE container encrypted using
// AES256GCM with key derivation based on PBES2_HS512_A256KW.
func ToEncryptedJWK(key *jose.JSONWebKey, secret []byte) (string, error) {
	// Check arguments
	if key == nil {
		return "", errors.New("unable to encrypt a nil key")
	}

	// Encode the JWK as JSON
	var out bytes.Buffer
	if err := json.NewEncoder(&out).Encode(key); err != nil {
		return "", fmt.Errorf("unable to encode JWK as JSON: %w", err)
	}

	// Initialize JWE
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm:  jose.PBES2_HS512_A256KW,
		Key:        secret,
		PBES2Count: 210000, // OWASP Recommendation - https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
	}, &jose.EncrypterOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderContentType: "application/jwk+json",
		},
	})
	if err != nil {
		return "", fmt.Errorf("unable to initialize JWE encrypter: %w", err)
	}

	// Encrypt the key
	jwe, err := encrypter.Encrypt(out.Bytes())
	if err != nil {
		return "", fmt.Errorf("unable to encrypt the key: %w", err)
	}

	// Serialize the final token
	token, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("unable to serialize final encrypted key: %w", err)
	}

	return token, nil
}

// FromJWK tries to decode the given reader content as JWK.
func FromJWK(r io.Reader) (*jose.JSONWebKey, error) {
	// Check arguments
	if r == nil {
		return nil, errors.New("input reader must not be nil")
	}

	// Drain content
	raw, err := io.ReadAll(io.LimitReader(r, maxJWKLength+1))
	if err != nil {
		return nil, fmt.Errorf("unable to drain input reader: %w", err)
	}
	if len(raw) > maxJWKLength {
		return nil, errors.New("JWK content is larger than expected")
	}

	// Decode the JWK
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("unable to decode the JWK content: %w", err)
	}

	// Check if the key is usable in the content
	if _, err := ExtractKey(jwk.Key); err != nil {
		return nil, fmt.Errorf("the JWK content has an unusal key for the context: %w", err)
	}

	return &jwk, nil
}

// FromEncryptedJWK unwraps the JWK encoded in a JWE container encrypted using
// AES256GCM with key derivation based on PBES2_HS512_A256KW.
func FromEncryptedJWK(r io.Reader, secret []byte) (*jose.JSONWebKey, error) {
	// Drain content
	raw, err := io.ReadAll(io.LimitReader(r, maxJWKLength+1))
	if err != nil {
		return nil, fmt.Errorf("unable to drain input reader: %w", err)
	}
	if len(raw) > maxJWKLength {
		return nil, errors.New("JWE content is larger than expected")
	}

	// Decoded the input JWE container
	jwe, err := jose.ParseEncrypted(string(raw))
	if err != nil {
		return nil, fmt.Errorf("unable to parse input JWE container: %w", err)
	}

	// Ensure expected content type
	typ, ok := jwe.Header.ExtraHeaders[jose.HeaderContentType]
	if !ok {
		return nil, fmt.Errorf("unable to decrypt the JWE container, empty content type")
	}
	if typ != "application/jwk+json" {
		return nil, fmt.Errorf("unable to decrypt the JWE container, unexpected content type %q", typ)
	}

	// Decrypt the JWE container
	out, err := jwe.Decrypt(secret)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt the JWE container")
	}

	// Unpack the key
	jwk, err := FromJWK(bytes.NewReader(out))
	if err != nil {
		return nil, fmt.Errorf("unable to decode wrapped JWK: %w", err)
	}

	return jwk, nil
}
