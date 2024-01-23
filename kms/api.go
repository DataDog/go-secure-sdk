package kms

import (
	"context"
	"crypto"
)

// Encryptor describes encryption operations contract.
type Encryptor interface {
	Encrypt(ctx context.Context, cleartext []byte) ([]byte, error)
}

// Decryptor describes decryption operations contract.
type Decryptor interface {
	Decrypt(ctx context.Context, encrypted []byte) ([]byte, error)
}

// Signer represents signature creation operations contract.
type Signer interface {
	Sign(ctx context.Context, protected []byte) ([]byte, error)
}

// Verifier represents signature verification operations contract.
type Verifier interface {
	Verify(ctx context.Context, protected, signature []byte) error
}

// KeyRotator represents key rotation operations contract.
type KeyRotator interface {
	RotateKey(ctx context.Context) error
}

// PublicKeyExporter represents public key operations contract.
type PublicKeyExporter interface {
	PublicKey(ctx context.Context) (crypto.PublicKey, error)
}

// VerificationPublicKeyExporter represents verification public key exporter contract.
type VerificationPublicKeyExporter interface {
	VerificationPublicKeys(ctx context.Context) ([]crypto.PublicKey, error)
}

// KeyExporter represents secret key exporter contract.
type KeyExporter interface {
	ExportKey(ctx context.Context) (KeyType, string, error)
}

//go:generate mockgen -destination mock/service.mock.go -package mock github.com/DataDog/go-secure-sdk/kms Service

// Service represents the Vault Transit backend operation service contract.
type Service interface {
	Encryptor
	Decryptor
	Signer
	Verifier
	PublicKeyExporter
	KeyRotator
	VerificationPublicKeyExporter
	KeyExporter
}

// KeyType represents the type of the key
type KeyType int

const (
	KeyTypeUnknown KeyType = iota
	KeyTypeSymmetric
	KeyTypeRSA
	KeyTypeEd25519
	KeyTypeECDSA
	KeyTypeHMAC
)
