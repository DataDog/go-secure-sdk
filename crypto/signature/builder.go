package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// FromPublicKey returns the associated verifier instance matching the public
// key type.
func FromPublicKey(pub crypto.PublicKey) (Verifier, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return ECDSAVerifier(k)
	case ed25519.PublicKey:
		return Ed25519Verifier(k)
	default:
	}

	return nil, fmt.Errorf("unsupported public key type %T", pub)
}

// FromPublicKeyPEM initializes a verifier instance from a PEM content.
func FromPublicKeyPEM(r io.Reader) (Verifier, error) {
	// Check arguments
	if r == nil {
		return nil, fmt.Errorf("reader must not be nil")
	}

	// Drain all reader content
	payload, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("unable to drain input reader content: %w", err)
	}

	// Decode public key
	pubRaw, _ := pem.Decode(payload)
	if pubRaw == nil {
		return nil, errors.New("input PEM looks to be empty")
	}

	// Check block type
	if pubRaw.Type != "PUBLIC KEY" {
		return nil, errors.New("input PEM should have PUBLIC KEY as block type")
	}

	// Parse public key
	k, err := x509.ParsePKIXPublicKey(pubRaw.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse input public key: %w", err)
	}

	// Delegate to builder
	return FromPublicKey(k)
}

// FromPrivateKey returns the associated signer instance matching the private
// key type.
func FromPrivateKey(pk crypto.Signer) (Signer, error) {
	switch k := pk.(type) {
	case *ecdsa.PrivateKey:
		return ECDSASigner(k)
	case ed25519.PrivateKey:
		return Ed25519Signer(k)
	default:
	}

	return nil, fmt.Errorf("unsupported private key type")
}

// FromPrivateKeyPEM initializes a signer instance from a PEM content.
func FromPrivateKeyPEM(r io.Reader) (Signer, error) {
	// Check arguments
	if r == nil {
		return nil, fmt.Errorf("reader must not be nil")
	}

	// Drain all reader content
	payload, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("unable to drain input reader content: %w", err)
	}

	// Decode public key
	privRaw, _ := pem.Decode(payload)
	if privRaw == nil {
		return nil, errors.New("input PEM looks to be empty")
	}

	// Check block type
	if privRaw.Type != "PRIVATE KEY" {
		return nil, errors.New("input PEM should have PRIVATE KEY as block type")
	}

	// Parse private key
	k, err := x509.ParsePKCS8PrivateKey(privRaw.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse input private key: %w", err)
	}

	// Ensure crypto signer instance
	pk, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("the encoded key can't be used to sign")
	}

	// Delegate to builder
	return FromPrivateKey(pk)
}
