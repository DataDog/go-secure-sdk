package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

// ECDSASigner returns an ECDSA signer according to the provided private key's curve.
func ECDSASigner(pk *ecdsa.PrivateKey) (Signer, error) {
	// Check arguments
	if pk == nil {
		return nil, errors.New("the private key is nil")
	}

	return &ecdsaSigner{
		pk:     pk,
		pubRaw: elliptic.MarshalCompressed(pk.Curve, pk.X, pk.Y),
	}, nil
}

// -----------------------------------------------------------------------------

type ecdsaSigner struct {
	pk     *ecdsa.PrivateKey
	pubRaw []byte
}

func (s *ecdsaSigner) Algorithm() Algorithm {
	switch s.pk.Curve {
	case elliptic.P256():
		return ECDSAP256Signature
	case elliptic.P384():
		return ECDSAP384Signature
	case elliptic.P521():
		return ECDSAP521Signature
	default:
	}

	return UnknownSignature
}

// Sign the protected content. It returns the ASN.1 encoded signature.
func (s *ecdsaSigner) Sign(protected []byte) ([]byte, error) {
	h, err := curveToHash(s.pk.Curve)
	if err != nil {
		return nil, fmt.Errorf("invalid or unsupported curve: %w", err)
	}

	// Compute message hash
	if _, err = h.Write(protected); err != nil {
		return nil, fmt.Errorf("unable to compute protected content digest: %w", err)
	}

	// Sign and return packed signature
	sig, err := ecdsa.SignASN1(rand.Reader, s.pk, h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("unable to sign with ECDSA: %w", err)
	}

	return sig, nil
}

// PublicKey returns the compressed point of the public key as byte.
func (s *ecdsaSigner) PublicKey() []byte {
	return s.pubRaw
}

// -----------------------------------------------------------------------------

func ECDSAVerifier(pub *ecdsa.PublicKey) (Verifier, error) {
	// Check arguments
	if pub == nil {
		return nil, errors.New("the public key is nil")
	}

	return &ecdsaVerifier{
		pub:    pub,
		pubRaw: elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y),
	}, nil
}

type ecdsaVerifier struct {
	pub    *ecdsa.PublicKey
	pubRaw []byte
}

func (s *ecdsaVerifier) Algorithm() Algorithm {
	switch s.pub.Curve {
	case elliptic.P256():
		return ECDSAP256Signature
	case elliptic.P384():
		return ECDSAP384Signature
	case elliptic.P521():
		return ECDSAP521Signature
	default:
	}

	return UnknownSignature
}

// Verify the ASN.1 encoded signature against the given protected content.
func (s *ecdsaVerifier) Verify(protected, signature []byte) error {
	h, err := curveToHash(s.pub.Curve)
	if err != nil {
		return err
	}

	// Compute message hash
	if _, err := h.Write(protected); err != nil {
		return fmt.Errorf("unable to compute protected content hash: %w", err)
	}

	// Verify signature
	if !ecdsa.VerifyASN1(s.pub, h.Sum(nil), signature) {
		return ErrInvalidSignature
	}

	return nil
}

// PublicKey returns the compressed point of the public key as byte.
func (s *ecdsaVerifier) PublicKey() []byte {
	return s.pubRaw
}

// -----------------------------------------------------------------------------

func curveToHash(c elliptic.Curve) (hash.Hash, error) {
	var h hash.Hash
	// Select appropriate hash function according to the given curve.
	switch c {
	case elliptic.P256():
		h = sha256.New()
	case elliptic.P384():
		h = sha512.New384()
	case elliptic.P521():
		h = sha512.New()
	default:
		return nil, errors.New("invalid curve")
	}

	return h, nil
}
