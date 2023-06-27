// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package signature

import (
	"crypto/ed25519"
	"errors"

	security "github.com/DataDog/go-secure-sdk"
)

// Ed25519Signer instantiates an EdDSA signer using the Ed25519 signature scheme.
//
// Disabled in FIPS Mode.
func Ed25519Signer(pk ed25519.PrivateKey) (Signer, error) {
	// Ensure an acceptable signer type according to enabled flags.
	if security.InFIPSMode() {
		return nil, errors.New("ed25519 signer usage is disabled in FIPS mode")
	}

	// Check arguments
	if len(pk) != ed25519.PrivateKeySize {
		return nil, errors.New("ed25519 private key is invalid")
	}
	pub := pk.Public()
	if pub == nil {
		return nil, errors.New("the ed25519 private key doesn't have an associated public key")
	}

	return &ed25519Signer{
		pk:     pk,
		pubRaw: pub.(ed25519.PublicKey),
	}, nil
}

// Ed25519Verifier instantiates an EdDSA verifier using the Ed25519 signature scheme.
//
// Disabled in FIPS Mode.
func Ed25519Verifier(pub ed25519.PublicKey) (Verifier, error) {
	// Ensure an acceptable signer type according to enabled flags.
	if security.InFIPSMode() {
		return nil, errors.New("ed25519 verifier usage is disabled in FIPS mode")
	}

	// Check arguments
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("ed25519 public key is invalid")
	}

	return &ed25519Verifier{
		pub: pub,
	}, nil
}

// -----------------------------------------------------------------------------

type ed25519Signer struct {
	pk     ed25519.PrivateKey
	pubRaw []byte
}

func (s *ed25519Signer) Algorithm() Algorithm {
	return Ed25519Signature
}

func (s *ed25519Signer) Sign(protected []byte) ([]byte, error) {
	sig := ed25519.Sign(s.pk, protected)
	return sig, nil
}

func (s *ed25519Signer) PublicKey() []byte {
	return s.pubRaw
}

// -----------------------------------------------------------------------------

type ed25519Verifier struct {
	pub ed25519.PublicKey
}

func (s *ed25519Verifier) Algorithm() Algorithm {
	return Ed25519Signature
}

func (s *ed25519Verifier) Verify(protected, signature []byte) error {
	if !ed25519.Verify(s.pub, protected, signature) {
		return ErrInvalidSignature
	}
	return nil
}

func (s *ed25519Verifier) PublicKey() []byte {
	return s.pub
}
