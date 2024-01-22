package keyutil

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/awnumar/memguard"

	"github.com/DataDog/go-secure-sdk/crypto/encryption"
)

const (
	maxPEMLength = 1 << 20 // 1MB
)

// ToDERBytes encodes the given crypto key as a byte array in ASN.1 DER Form.
// It returns the PEM block type as string, and the encoded key.
//
// A private key will be serialized using PKCS8.
// Supported private types: *rsa.PrivateKey, *ecdsa.PrivateKey, *ecdh.PrivateKey,
// ed25519.PrivateKey
//
// A public key will be serialized using PKIX.
// Supported public key types: *rsa.PublicKey, *ecdsa.PublicKey, *ecdh.PublicKey,
// ed25519.PublicKey
func ToDERBytes(key any) (string, []byte, error) {
	// Check key
	if key == nil {
		return "", nil, errors.New("unable to encode nil key")
	}

	var (
		out []byte
		err error
	)
	switch k := key.(type) {
	// Private keys ------------------------------------------------------------
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, *ecdh.PrivateKey:
		out, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return "", nil, fmt.Errorf("unable to serialize key: %w", err)
		}
		return "PRIVATE KEY", out, nil
	// Public keys -------------------------------------------------------------
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *ecdh.PublicKey:
		out, err = x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return "", nil, fmt.Errorf("unable to serialize key: %w", err)
		}
		return "PUBLIC KEY", out, nil
	default:
	}

	return "", nil, fmt.Errorf("given key type is not supported")
}

// ToPEM encodes the given crypto key as a PEM block.
//
// A private key will be serialized using PKCS8.
// Supported private types: *rsa.PrivateKey, *ecdsa.PrivateKey, *ecdh.PrivateKey,
// ed25519.PrivateKey
//
// A public key will be serialized using PKIX.
// Supported public key types: *rsa.PublicKey, *ecdsa.PublicKey, *ecdh.PublicKey,
// ed25519.PublicKey
func ToPEM(w io.Writer, key any) error {
	// Check arguments
	if w == nil {
		return errors.New("output writer must not be nil")
	}

	// Transform the key
	hdr, content, err := ToDERBytes(key)
	if err != nil {
		return fmt.Errorf("unable to transform the given key: %w", err)
	}

	// Prepare the block
	if err := pem.Encode(w, &pem.Block{
		Type:  hdr,
		Bytes: content,
	}); err != nil {
		return fmt.Errorf("unable to encode final PEM block: %w", err)
	}

	return nil
}

// ToCabinPEM encrypts the given key with the given password in a secret cabin.
//
// A private key will be serialized using PKCS8.
// Supported private types: *rsa.PrivateKey, *ecdsa.PrivateKey, *ecdh.PrivateKey,
// ed25519.PrivateKey
//
// A public key will be serialized using PKIX.
// Supported public key types: *rsa.PublicKey, *ecdsa.PublicKey, *ecdh.PublicKey,
// ed25519.PublicKey
func ToCabinPEM(w io.Writer, key any, password []byte) error {
	// Check arguments
	if w == nil {
		return errors.New("output writer must not be nil")
	}

	// Transform the key
	hdr, content, err := ToDERBytes(key)
	if err != nil {
		return fmt.Errorf("unable to transform the given key: %w", err)
	}

	// Seal the secret cabin
	var out bytes.Buffer
	if err := encryption.SealSecretCabin(&out, memguard.NewBufferFromBytes(content), password); err != nil {
		return fmt.Errorf("unable to seal the secret cabin: %w", err)
	}

	// Prepare the block
	if err := pem.Encode(w, &pem.Block{
		Type:  fmt.Sprintf("ENCRYPTED CABIN %s", hdr),
		Bytes: out.Bytes(),
	}); err != nil {
		return fmt.Errorf("unable to encode final PEM block: %w", err)
	}

	return nil
}

// FromPEM opens a cryptographic key packaged in a PEM block.
//
// A private key will be deserialized using PKCS8.
// Supported private types: *rsa.PrivateKey, *ecdsa.PrivateKey, *ecdh.PrivateKey,
// ed25519.PrivateKey
//
// A public key will be deserialized using PKIX.
// Supported public key types: *rsa.PublicKey, *ecdsa.PublicKey, *ecdh.PublicKey,
// ed25519.PublicKey
func FromPEM(r io.Reader) (any, error) {
	// Check arguments
	if r == nil {
		return nil, errors.New("input reader must not be nil")
	}

	// Extract content from the reader (limited to 1MB)
	payload, err := io.ReadAll(io.LimitReader(r, maxPEMLength+1))
	if err != nil {
		return nil, fmt.Errorf("unable to drain input reader: %w", err)
	}
	if len(payload) > maxPEMLength {
		return nil, errors.New("PEM content is larger than expected")
	}

	// Decode PEM structure
	b, _ := pem.Decode(payload)
	if b == nil {
		return nil, errors.New("invalid PEM block")
	}

	// Decode key
	var (
		key       any
		errDecode error
	)
	switch b.Type {
	case "PRIVATE KEY":
		key, errDecode = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "PUBLIC KEY":
		key, errDecode = x509.ParsePKIXPublicKey(b.Bytes)
	default:
		return nil, fmt.Errorf("unsupported block type %q", b.Type)
	}
	if errDecode != nil {
		return nil, fmt.Errorf("unable to decode key: %w", errDecode)
	}

	return key, nil
}

// FromCabinPEM opens and decrypt a cryptographic key packaged in a secret cabin.
//
// A private key will be deserialized using PKCS8.
// Supported private types: *rsa.PrivateKey, *ecdsa.PrivateKey, *ecdh.PrivateKey,
// ed25519.PrivateKey
//
// A public key will be deserialized using PKIX.
// Supported public key types: *rsa.PublicKey, *ecdsa.PublicKey, *ecdh.PublicKey,
// ed25519.PublicKey
func FromCabinPEM(r io.Reader, password []byte) (any, error) {
	// Check arguments
	if r == nil {
		return nil, errors.New("input reader must not be nil")
	}

	// Extract content from the reader (limited to 1MB)
	payload, err := io.ReadAll(io.LimitReader(r, maxPEMLength+1))
	if err != nil {
		return nil, fmt.Errorf("unable to drain input reader: %w", err)
	}
	if len(payload) > maxPEMLength {
		return nil, errors.New("PEM content is larger than expected")
	}

	// Decode PEM structure
	b, _ := pem.Decode(payload)
	if b == nil {
		return nil, errors.New("invalid PEM block")
	}

	// Open secret cabin
	lb, err := encryption.ParseSecretCabin(b.Bytes, password)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt the secret cabin: %w", err)
	}

	// Ensure appropriate header
	var (
		key       any
		errDecode error
	)
	switch b.Type {
	case "ENCRYPTED CABIN PRIVATE KEY":
		key, errDecode = x509.ParsePKCS8PrivateKey(lb.Bytes())
	case "ENCRYPTED CABIN PUBLIC KEY":
		key, errDecode = x509.ParsePKIXPublicKey(lb.Bytes())
	default:
		return nil, fmt.Errorf("unsupported block type %q", b.Type)
	}
	if errDecode != nil {
		return nil, fmt.Errorf("unable to decode key: %w", errDecode)
	}

	return key, nil
}
