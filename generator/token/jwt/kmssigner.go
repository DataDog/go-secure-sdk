package jwt

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	jose "gopkg.in/square/go-jose.v2"

	"github.com/DataDog/go-secure-sdk/crypto/keyutil"
	"github.com/DataDog/go-secure-sdk/crypto/signature"
	"github.com/DataDog/go-secure-sdk/kms"
)

// KMSSigner initalizes a remote KMS signer to be used for JWT signing.
func KMSSigner(ctx context.Context, service kms.Service) (Signer, error) {
	// Check arguments
	if ctx == nil {
		ctx = context.Background()
	}
	if service == nil {
		return nil, errors.New("kms service must not be nil")
	}

	// Retrieve remote public key
	pub, err := service.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve the remote public key: %w", err)
	}

	// Try to build a verifier from the public key
	verifier, err := signature.FromPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("unable to build a local verifier from the public key: %w", err)
	}

	// Export Public key as JWK (expose it using a dedicated endpoint to allow
	// identity consumers to retrieve it)
	pubJwk, err := keyutil.ToJWK(pub)
	if err != nil {
		return nil, fmt.Errorf("unable to encode the public key as JWK: %w", err)
	}

	return &kmsSigner{
		ctx:      ctx,
		signer:   service,
		verifier: verifier,
		pubJwk:   *pubJwk,
	}, nil
}

// -----------------------------------------------------------------------------

type kmsSigner struct {
	ctx      context.Context
	signer   kms.Signer
	verifier signature.Verifier
	pubJwk   jose.JSONWebKey
}

func (ts *kmsSigner) Alg() string {
	switch ts.verifier.Algorithm() {
	case signature.ECDSAP256Signature:
		return "ES256"
	case signature.ECDSAP384Signature:
		return "ES384"
	case signature.ECDSAP521Signature:
		return "ES521"
	case signature.Ed25519Signature:
		return "EdDSA"
	default:
	}

	return ""
}

func (ts *kmsSigner) Sign(protected string, _ any) (string, error) {
	// Prepare a sub context
	ctx, cancel := context.WithTimeout(ts.ctx, 30*time.Second)
	defer cancel()

	// Delegate to the kms.
	sig, err := ts.signer.Sign(ctx, []byte(protected))
	if err != nil {
		return "", fmt.Errorf("unable to sign the token using KMS signer: %w", err)
	}

	return string(sig), nil
}

func (ts *kmsSigner) Verify(protected, sig string, _ any) error {
	// Decode signature (Assume JWS encoded signature)
	sigRaw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("unable to decode signature: %w", err)
	}

	// Use local verifier
	if err := ts.verifier.Verify([]byte(protected), sigRaw); err != nil {
		return fmt.Errorf("unable to verify the signature: %w", err)
	}

	return nil
}

func (ts *kmsSigner) KeyID() string {
	return ts.pubJwk.KeyID
}
