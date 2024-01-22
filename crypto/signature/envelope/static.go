package envelope

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/DataDog/go-secure-sdk/crypto/signature"
	protectedv1 "github.com/DataDog/go-secure-sdk/crypto/signature/envelope/internal/v1"
	protectedv2 "github.com/DataDog/go-secure-sdk/crypto/signature/envelope/internal/v2"
)

// WrapAndSign wraps the input payload in a given envelope and sign the content.
func WrapAndSign(contentType string, payload []byte, signer signature.Signer, opts ...Option) (*Envelope, error) {
	// Check arguments
	if contentType == "" {
		return nil, errors.New("content type must be defined")
	}
	if signer == nil {
		return nil, errors.New("signer must not be nil")
	}

	// Default options
	dopts := &options{
		timestamp: uint64(time.Now().Unix()),
	}

	// Apply options
	for _, o := range opts {
		o(dopts)
	}

	// Ensure public key
	pub := signer.PublicKey()
	if len(pub) == 0 {
		return nil, errors.New("signer has an empty public key")
	}

	// Compute checksums
	hPub := protectedv2.ComputeKeyID(pub)

	// Retrieve signer algorithm identifier
	alg := signer.Algorithm()

	// Compute protected content
	protected, err := protectedv2.ComputeProtected(alg, dopts.timestamp, hPub[:], []byte(contentType), payload)
	if err != nil {
		return nil, fmt.Errorf("unable to compute protected content: %w", err)
	}

	// Sign the protected content
	sig, err := signer.Sign(protected)
	if err != nil {
		return nil, fmt.Errorf("unable to sign the message: %w", err)
	}

	return &Envelope{
		ContentType: contentType,
		Content:     payload[:],
		Signature: &Signature{
			Version:     protectedv2.Version,
			Algorithm:   alg,
			PublicKeyID: hPub[:],
			Proof:       sig,
			Timestamp:   dopts.timestamp,
		},
	}, nil
}

// VerifyAndUnwrap verifies the envelope signature and return the verified content.
func VerifyAndUnwrap(e *Envelope, verifier signature.Verifier) ([]byte, error) {
	// Check arguments
	if e == nil {
		return nil, ErrInvalidEnvelope
	}
	if e.Signature == nil {
		return nil, ErrInvalidEnvelope
	}
	if verifier == nil {
		return nil, errors.New("verifier must not be nil")
	}

	// Ensure supported version to prevent downgrade attack.
	if e.Signature.Version < LowestSupportedVersion {
		return nil, errors.New("this signature version is not supported anymore")
	}

	// Ensure signer algorithm
	if e.Signature.Algorithm != verifier.Algorithm() {
		return nil, fmt.Errorf("algorithm mismatch, incorrect verifier: %w", ErrInvalidEnvelope)
	}

	// Ensure public key
	pub := verifier.PublicKey()
	if len(pub) == 0 {
		return nil, errors.New("verifier has an empty public key")
	}

	// Compute checksums
	var hPub [32]byte
	switch e.Signature.Version {
	case protectedv1.Version:
		hPub = protectedv1.ComputeKeyID(pub)
	case protectedv2.Version:
		hPub = protectedv2.ComputeKeyID(pub)
	default:
		return nil, errors.New("unsupported signature algorithm version")
	}

	// Ensure equality
	if !bytes.Equal(e.Signature.PublicKeyID, hPub[:]) {
		return nil, fmt.Errorf("public key identifier mismatch, expected %x, got %x: %w", hPub, e.Signature.PublicKeyID, ErrInvalidEnvelope)
	}

	var (
		protected           []byte
		errCanonicalization error
	)
	switch e.Signature.Version {
	case protectedv1.Version:
		protected, errCanonicalization = protectedv1.ComputeProtected(e.Signature.Algorithm, e.Signature.Nonce, e.Signature.PublicKeyID, []byte(e.ContentType), e.Content)
	case protectedv2.Version:
		protected, errCanonicalization = protectedv2.ComputeProtected(e.Signature.Algorithm, e.Signature.Timestamp, e.Signature.PublicKeyID, []byte(e.ContentType), e.Content)
	default:
		return nil, errors.New("unsupported signature algorithm version")
	}
	if errCanonicalization != nil {
		return nil, fmt.Errorf("unable to compute protected content: %w", errCanonicalization)
	}

	// Sign the protected content
	if err := verifier.Verify(protected, e.Signature.Proof); err != nil {
		return nil, signature.ErrInvalidSignature
	}

	// Unmarshal content
	return e.Content, nil
}
