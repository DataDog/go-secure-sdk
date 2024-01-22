package signature

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"time"

	security "github.com/DataDog/go-secure-sdk"
	"github.com/DataDog/go-secure-sdk/kms"
)

// RemoteSigner instantiates a signer which will use the remote KMS service as
// a private key holder and will send all signature request to this KMS.
//
//nolint:contextcheck // Non-inherited context error is a false positive
func RemoteSigner(ctx context.Context, remote kms.Service, opts ...KMSOption) (Signer, error) {
	// Check arguments
	if remote == nil {
		return nil, errors.New("KMS signer service must not be nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare default options
	dopts := &kmsOptions{
		timeout: 30 * time.Second,
	}
	for _, o := range opts {
		o(dopts)
	}

	// Retrieve public key
	pub, err := remote.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve remote public key: %w", err)
	}

	// Ensure a usable key type
	if _, ok := pub.(ed25519.PublicKey); ok && security.InFIPSMode() {
		return nil, errors.New("ed25519 key usage is disabled in FIPS Mode")
	}

	// Encode as bytes
	pubRaw, err := serializePublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("unable to encode the given public key: %w", err)
	}

	return &kmsSigner{
		ctx:              ctx,
		remote:           remote,
		publicKey:        pub,
		encodedPublicKey: pubRaw,
		dopts:            dopts,
	}, nil
}

type kmsSigner struct {
	ctx              context.Context
	remote           kms.Service
	publicKey        crypto.PublicKey
	encodedPublicKey []byte
	dopts            *kmsOptions
}

func (s *kmsSigner) Algorithm() Algorithm {
	switch k := s.publicKey.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return ECDSAP256Signature
		case elliptic.P384():
			return ECDSAP384Signature
		case elliptic.P521():
			return ECDSAP521Signature
		default:
		}
	case ed25519.PublicKey:
		return Ed25519Signature
	default:
	}

	return UnknownSignature
}

func (s *kmsSigner) Sign(protected []byte) ([]byte, error) {
	// Check arguments
	if s.ctx == nil {
		s.ctx = context.Background()
	}

	// Create child context
	ctx, cancel := context.WithTimeout(s.ctx, s.dopts.timeout)
	defer cancel()

	// Delegate to remote signer
	sig, err := s.remote.Sign(ctx, protected)
	if err != nil {
		return nil, fmt.Errorf("remote signer failed to sign the protected content: %w", err)
	}

	return sig, nil
}

func (s *kmsSigner) PublicKey() []byte {
	return s.encodedPublicKey
}

// -----------------------------------------------------------------------------

// RemoteVerifier instantiates a local verifier based on the remote public key
// stored in Vault. This implementation doesn't handle key rotation, it will
// pull automatically the latest version of the target key.
//
//nolint:contextcheck // Non-inherited context error is a false positive
func RemoteVerifier(ctx context.Context, remote kms.PublicKeyExporter) (Verifier, error) {
	// Check arguments
	if remote == nil {
		return nil, errors.New("KMS service must not be nil")
	}

	// Retrieve public key
	pub, err := remote.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve remote public key: %w", err)
	}

	// Delegate to public key builder to instantiate the appropriate verifier
	// instance.
	return FromPublicKey(pub)
}

// -----------------------------------------------------------------------------

// KMSOption describes the functional pattern used for optional settings.
type KMSOption func(*kmsOptions)

type kmsOptions struct {
	timeout time.Duration
}

// WithKMSTimeout defines the KMS operation timeout value.
func WithKMSTimeout(d time.Duration) KMSOption {
	return func(ko *kmsOptions) {
		ko.timeout = d
	}
}

// -----------------------------------------------------------------------------

func serializePublicKey(pub crypto.PublicKey) ([]byte, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("public key is nil")
		}
		return elliptic.MarshalCompressed(k.Curve, k.X, k.Y), nil
	case ed25519.PublicKey:
		if k == nil {
			return nil, errors.New("public key is nil")
		}
		return []byte(k), nil
	default:
	}

	return nil, errors.New("unsupported public key type")
}
