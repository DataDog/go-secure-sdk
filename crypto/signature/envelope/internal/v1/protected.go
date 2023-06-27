// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"crypto/sha512"

	"github.com/DataDog/go-secure-sdk/crypto/signature"
)

const Version = uint8(0x01)

// ComputeProtected is used to assemble the protected content to be signed/verified.
//
// For new code, use envelope canonicalization v2.
func ComputeProtected(algorithm signature.Algorithm, nonce, kid, contentType, payload []byte) ([]byte, error) {
	// Prepare body
	body := append([]byte{}, contentType...)
	body = append(body, 0x00)
	body = append(body, payload...)

	// Compute content hash
	hContent := sha512.Sum512_256(body)

	// Assemble protected specification
	protected := []byte("datadog-envelope-signature-v1")
	protected = append(protected, 0x00)
	protected = append(protected, []byte(algorithm)...)
	protected = append(protected, 0x00)
	protected = append(protected, nonce...)
	protected = append(protected, kid...)
	protected = append(protected, hContent[:]...)

	return protected, nil
}

// ComputeKeyID is used to generate the key identifier from the serialized
// public key.
//
// Deprecated. SHA512 doesn't have hardware acceleration on Go 1.19.5.
func ComputeKeyID(pub []byte) [32]byte {
	return sha512.Sum512_256(pub)
}
