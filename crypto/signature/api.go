// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package signature

import (
	"errors"
)

//go:generate mockgen -destination test/mock/signer.gen.go -package mock github.com/DataDog/go-secure-sdk/crypto/signature Signer

// Signer describes signature producer contract.
type Signer interface {
	// Algorithm identifier for the signer implementation
	Algorithm() Algorithm
	// Sign the given protected content and returns the raw signature.
	Sign(protected []byte) ([]byte, error)
	// PublicKey returns the associated public key encoded as byte
	PublicKey() []byte
}

//go:generate mockgen -destination test/mock/verifier.gen.go -package mock github.com/DataDog/go-secure-sdk/crypto/signature Verifier

// Verifier describes signature verifier contract.
type Verifier interface {
	// Algorithm identifier for the verifier implementation
	Algorithm() Algorithm
	// Verify a protected content signature.
	Verify(protected, signature []byte) error
	// PublicKey returns the associated public key encoded as byte
	PublicKey() []byte
}

// -----------------------------------------------------------------------------

// ErrInvalidSignature is raised when there is a signature mismatch.
var ErrInvalidSignature = errors.New("invalid signature")
