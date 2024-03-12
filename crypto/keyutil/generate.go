package keyutil

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	jose "github.com/go-jose/go-jose/v4"

	security "github.com/DataDog/go-secure-sdk"

	"golang.org/x/crypto/ssh"
)

var (
	// DefaultRSAKeySize is the default size (in # of bits) of a RSA private key.
	// FIPS-140 level 2 and 3 requires RSA key size to have 2048bits minimum.
	defaultRSAKeySize = 2048
	// DefaultECKeyCurve is the default curve of a EC private key.
	defaultECKeyCurve = elliptic.P256()
)

// KeyType repesents the key generation strategy
type KeyType uint

// Keeping 0 for PLATFORM preferred key if one day we support FIPS build flag.
const (
	// ED25519 defines Edwards 25519 key.
	ED25519 KeyType = iota + 1
	// EC defines EC P-256 key.
	EC
	// RSA defines RSA 2048 key.
	RSA
)

// GenerateDefaultKeyPair generates a cryptogrpahic key pair according to the
// framework enabled flags.
//
// FIPS Mode *enabled* => EC
//
// FIPS Mode *disabled* => OKP (Ed25519)
func GenerateDefaultKeyPair() (crypto.PublicKey, crypto.PrivateKey, error) {
	// Use EC key type as default for FIPS compliance mode
	if security.InFIPSMode() {
		return GenerateKeyPair(EC)
	}

	return GenerateKeyPair(ED25519)
}

// GenerateKeyPair generates a key pair according to the selected keytype.
func GenerateKeyPair(kty KeyType) (crypto.PublicKey, crypto.PrivateKey, error) {
	// Ensure a correct key type according to enabled flags.
	if security.InFIPSMode() && kty == ED25519 {
		return nil, nil, errors.New("Ed25519 key type generation is disabled in FIPS mode")
	}

	return GenerateKeyPairWithRand(rand.Reader, kty)
}

// GenerateKeyPairWithRand generates a key pair according to the selected keytype
// and allow a custom randsource to be used.
//
// FYI, RSA key generation Go implementation can't be deterministic by design.
// https://github.com/golang/go/issues/38548
func GenerateKeyPairWithRand(r io.Reader, kty KeyType) (crypto.PublicKey, crypto.PrivateKey, error) {
	// Check arguments
	if r == nil {
		return nil, nil, errors.New("random reader must not be nil")
	}

	switch kty {
	case RSA:
		// RSA key generation can't be deterministic by design, ensure the crypto
		// random source to be used by default.
		// https://github.com/golang/go/issues/38548
		pk, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to generate RSA key pair: %w", err)
		}
		return pk.Public(), pk, nil
	case EC:
		// Using Go 1.19.5 ecdsa key generation. Go >=1.20 uses non-deterministic
		// key generation.
		pk, err := ecdsa.GenerateKey(defaultECKeyCurve, rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to generate EC key pair: %w", err)
		}
		return pk.Public(), pk, nil
	case ED25519:
		// Ensure a correct key type according to enabled flags.
		if security.InFIPSMode() {
			return nil, nil, errors.New("Ed25519 key type generation is disabled in FIPS mode")
		}

		pub, pk, err := ed25519.GenerateKey(r)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to generate OKP key pair: %w", err)
		}
		return pub, pk, nil
	default:
	}

	return nil, nil, errors.New("key type not supported")
}

// PublicKey extracts a public key from a private key.
func PublicKey(priv any) (crypto.PublicKey, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		if k == nil {
			return nil, errors.New("private key is nil")
		}
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		if k == nil {
			return nil, errors.New("private key is nil")
		}
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		if k == nil {
			return nil, errors.New("private key is nil")
		}
		return k.Public(), nil
	case *ecdh.PrivateKey:
		if k == nil {
			return nil, errors.New("private key is nil")
		}
		return k.Public(), nil
	case jose.JSONWebKey:
		if k.IsPublic() {
			return k.Key, nil
		}
		return k.Public().Key, nil
	case *jose.JSONWebKey:
		if k == nil {
			return nil, errors.New("private key is nil")
		}
		if k.IsPublic() {
			return k.Key, nil
		}
		return k.Public().Key, nil
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *ecdh.PublicKey:
		if k == nil {
			return nil, errors.New("public key is nil")
		}
		return k, nil
	default:
		return nil, fmt.Errorf("unrecognized key type: %T", priv)
	}
}

// ExtractKey returns the given public or private key or extracts the public key
// if a x509.Certificate or x509.CertificateRequest is given.
func ExtractKey(in any) (any, error) {
	switch k := in.(type) {
	case *rsa.PublicKey, *rsa.PrivateKey,
		*ecdsa.PublicKey, *ecdsa.PrivateKey,
		*ecdh.PublicKey, *ecdh.PrivateKey,
		ed25519.PublicKey, ed25519.PrivateKey:
		return in, nil
	case []byte:
		return in, nil
	case *x509.Certificate:
		return k.PublicKey, nil
	case *x509.CertificateRequest:
		return k.PublicKey, nil
	case ssh.CryptoPublicKey:
		return k.CryptoPublicKey(), nil
	case *ssh.Certificate:
		return ExtractKey(k.Key)
	case jose.JSONWebKey:
		return k.Key, nil
	case *jose.JSONWebKey:
		return k.Key, nil
	default:
		return nil, fmt.Errorf("cannot extract the key from type '%T'", k)
	}
}

// VerifyPair that the public key matches the given private key.
func VerifyPair(pubkey crypto.PublicKey, key crypto.PrivateKey) error {
	switch pub := pubkey.(type) {
	case *rsa.PublicKey:
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("private key type does not match public key type")
		}
		if !pub.Equal(priv.Public()) {
			return errors.New("private key does not match public key")
		}
	case *ecdsa.PublicKey:
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("private key type does not match public key type")
		}
		if !pub.Equal(priv.Public()) {
			return errors.New("private key does not match public key")
		}
	case ed25519.PublicKey:
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return errors.New("private key type does not match public key type")
		}
		if !pub.Equal(priv.Public()) {
			return errors.New("private key does not match public key")
		}
	case *ecdh.PublicKey:
		priv, ok := key.(*ecdh.PrivateKey)
		if !ok {
			return errors.New("private key type does not match public key type")
		}
		if !pub.Equal(priv.Public()) {
			return errors.New("private key does not match public key")
		}
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
	return nil
}

// VerifyPublicKey verifies that the given public key matches the given input.
func VerifyPublicKey(input any, key crypto.PublicKey) error {
	// Extract public key from input
	pubkey, err := PublicKey(input)
	if err != nil {
		return fmt.Errorf("unable to extract public key from the input: %w", err)
	}

	// Check if the public key matches
	switch pub := pubkey.(type) {
	case *rsa.PublicKey:
		if !pub.Equal(key) {
			return errors.New("private key does not match public key")
		}
	case *ecdsa.PublicKey:
		if !pub.Equal(key) {
			return errors.New("private key does not match public key")
		}
	case ed25519.PublicKey:
		if !pub.Equal(key) {
			return errors.New("private key does not match public key")
		}
	case *ecdh.PublicKey:
		if !pub.Equal(key) {
			return errors.New("private key does not match public key")
		}
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}

	return nil
}
