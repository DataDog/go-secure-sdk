// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package keyutil

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// subjectPublicKeyInfo is a PKIX public key structure defined in RFC 5280.
type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// PublicKeyFingerprint generates a public key fingerprint.
// https://www.rfc-editor.org/rfc/rfc6698
//
// This fingerprint algorithm marshal the public key using PKIX ASN.1 to DER
// content. The ASN.1 is processed to retrieve the SubjectPublicKey content from
// the ASN.1 serialized and compute the SHA256 of the SubjectPublicKey content.
func PublicKeyFingerprint(key any) ([]byte, error) {
	// Check arguments
	if key == nil {
		return nil, errors.New("key must not be nil")
	}

	// Extract public key
	k, err := ExtractKey(key)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve a key from the given input: %w", err)
	}

	// Ensure a public key
	pub, err := PublicKey(k)
	if err != nil {
		return nil, fmt.Errorf("unable to public key: %w", err)
	}

	// Marshal the public key as DER
	out, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize key: %w", err)
	}

	// Extract unwrapped public key content.
	var info subjectPublicKeyInfo
	if _, err = asn1.Unmarshal(out, &info); err != nil {
		return nil, fmt.Errorf("unable to extract DER content from the encoded public key: %w", err)
	}

	// Compute SHA256 checksum of the public key.
	h := sha256.Sum256(info.SubjectPublicKey.Bytes)

	return h[:], nil
}
