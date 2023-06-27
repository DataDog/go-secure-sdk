// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package provider provides Key provider contract and standard implementations.
package provider

import (
	"crypto"
	"crypto/cipher"
	"errors"
	"fmt"
	"hash"

	"github.com/DataDog/go-secure-sdk/crypto/encryption"
	"github.com/DataDog/go-secure-sdk/crypto/keyutil"
	"github.com/DataDog/go-secure-sdk/crypto/signature"
	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

// ErrKeyNotFound is raised when the key resolution failed.
var ErrKeyNotFound = errors.New("key could not be resolved from the current provider content")

const (
	generatedKeyAliasFormat = "urn:datadog:kms:v1:%s"
)

// KeyAlias represents key provider handle.
type KeyAlias string

func newKeyAlias() (KeyAlias, error) {
	// Generate key alias
	suffix, err := randomness.Alphanumeric(32)
	if err != nil {
		return "", fmt.Errorf("unable to generate key alias suffix: %w", err)
	}

	return KeyAlias(fmt.Sprintf(generatedKeyAliasFormat, suffix)), nil
}

// KeyPurpose is a UInt8 value packing key capabilities as bit fields.
type KeyPurpose uint8

const (
	// SignaturePurpose describes the signature bit in the purpose flags for
	// the key.
	SignaturePurpose KeyPurpose = 1 + iota
	// EncryptionPurpose describes the encryption bit in the purpose flags of
	// the key.
	EncryptionPurpose
	// KeyDerivationPurpose describes the key derivation bit in the purpose
	// flags of the key.
	KeyDerivationPurpose
	// ExportableKey enables key exportation operations.
	ExportableKey

	// LastKeyPurpose indicates the last acceptable value. Ensure that your add
	// new flags before this one.
	lastKeyPurpose
)

// KeyPurposes represents key purposes bit set.
type KeyPurposes uint32

// Can check if the purpose flag is set.
func (kp KeyPurposes) Can(purpose KeyPurpose) bool {
	return purpose < lastKeyPurpose && kp&(1<<(uint32(purpose)-1)) > 0
}

// Set the purpose flag.
func (kp KeyPurposes) Set(purpose KeyPurpose) KeyPurposes {
	if purpose > lastKeyPurpose {
		return kp
	}
	return kp | (1 << (uint32(purpose) - 1))
}

// Clear the purpose flag.
func (kp KeyPurposes) Clear(purpose KeyPurpose) KeyPurposes {
	if purpose > lastKeyPurpose {
		return kp
	}
	return kp &^ (1 << (uint32(purpose) - 1))
}

// Purposes packs key purpose together.
func Purposes(purposes ...KeyPurpose) KeyPurposes {
	var kp KeyPurposes
	for _, p := range purposes {
		kp = kp.Set(p)
	}
	return kp
}

// KeyFactory describes key factory function.
type KeyFactory func(alias KeyAlias) (Key, error)

// Key describes the item type stored in the key provider.
type Key interface {
	// Can consults key purpose and returns trus if the given purpose matches
	// one of the key purpose
	Can(purpose KeyPurpose) bool

	// Alias returns the registered key alias.
	Alias() KeyAlias
}

// AsymmetricKey describes asymmetric key provider item.
type AsymmetricKey interface {
	Key

	// Public returns the Go crypto.PublicKey.
	Public() crypto.PublicKey
}

// PublicKey describes the public side of an asymmetric key pair.
type PublicKey interface {
	AsymmetricKey

	// AsBytes exports the public key using PKIX ASN.1 encoding.
	AsBytes() ([]byte, error)
	// AsPEM returns the public key encoded with PKIX PEM.
	AsPEM() (string, error)
	// AsJWK returns the public key encoded as a JSON Web Key.
	AsJWK() (string, error)
	// Verifier returns a verifier created from the public key.
	Verifier() (signature.Verifier, error)
}

// PrivateKey describes the private side of an asymmetric key pair.
type PrivateKey interface {
	AsymmetricKey

	// Signer returns a signer if the key can be used for signing purpose.
	Signer() (signature.Signer, error)
}

// SymmetricKey describes symmetric key provider item.
type SymmetricKey interface {
	Key

	// AsBytes exports the symmetric key as byte array if the key is flagged as
	// exportable.
	AsBytes() ([]byte, error)
	// ValueEncryption returns a single value encryption system initialized with
	// the symmetric key.
	ValueEncryption() (encryption.ValueAEAD, error)
	// ChunkedEncryption returns a chunked encryption system initialized with
	// the symmetric key.
	ChunkedEncryption() (encryption.ChunkedAEAD, error)
	// ConvergentEncryption returns a convergent encryption system initialized
	// with the symmetric key.
	ConvergentEncryption() (encryption.ValueAEAD, error)
	// HMAC initializes a HMAC function using the symmetric key.
	HMAC(h func() hash.Hash) (hash.Hash, error)
	// NewCipher initializes a new block cipher using the symmetric key.
	NewCipher() (cipher.Block, error)
	// Derive a symmetric key based on the given salt and information.
	DeriveSymmetric(salt, info []byte, dkLen uint32, purposes ...KeyPurpose) (SymmetricKey, error)
	// Derive an asymmetric key pair based on the given salt and information.
	DeriveAsymmetric(salt, info []byte, kty keyutil.KeyType, purposes ...KeyPurpose) (PublicKey, PrivateKey, error)
}

// -----------------------------------------------------------------------------

// KeyResolver describes key resolution operations for a key provider.
type KeyResolver interface {
	// GetSymmetricFor resolves the key alias expecting a symmetric key matching the given purpose.
	GetSymmetricFor(alias KeyAlias, purpose KeyPurpose) (SymmetricKey, error)
	// GetPrivateFor resolves the key alias expecting a private key matching the gievn purpose.
	GetPrivateFor(alias KeyAlias, purpose KeyPurpose) (PrivateKey, error)
	// GetPublic resolves the key alias expecting a public key.
	GetPublic(alias KeyAlias) (PublicKey, error)
}

// KeyGenerator describes key generation operations for a key provider.
type KeyGenerator interface {
	// GenerateKeyPair and store the keys in the key provider for dedicated purposes.
	GenerateKeyPair(kty keyutil.KeyType, purposes ...KeyPurpose) (PrivateKey, error)
	// GenerateSecret generates a random secret value based on the input length.
	// The length must be greater than 16 and lower than 1024 to be acceptable.
	GenerateSecret(length int, purposes ...KeyPurpose) (SymmetricKey, error)
}

// KeyRegistry describes key provider registry operations.
type KeyRegistry interface {
	// Register a key from the delegated factory to the associated key alias.
	Register(alias KeyAlias, keyFactory KeyFactory) error
	// Remove the given key matching the alias.
	Remove(alias KeyAlias) error
}

// KeyProvider represents the complete contract of a key provider.
type KeyProvider interface {
	KeyResolver
	KeyGenerator
}

// MutableKeyProvider extends the KeyProvider contract to add key management operations.
type MutableKeyProvider interface {
	KeyProvider
	KeyRegistry
}
