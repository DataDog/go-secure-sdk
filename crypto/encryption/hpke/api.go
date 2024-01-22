// Package hpke provides RFC9180 hybrid public key encryption features.
package hpke

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/DataDog/go-secure-sdk/crypto/kem"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type mode uint8

const (
	modeBase    mode = 0x00
	modePsk     mode = 0x01
	modeAuth    mode = 0x02
	modeAuthPsk mode = 0x03
)

// -----------------------------------------------------------------------------

type KEM uint16

//nolint:stylecheck
const (
	// KEM_P256_HKDF_SHA256 is a KEM using P-256 curve and HKDF with SHA-256.
	KEM_P256_HKDF_SHA256 KEM = 0x10
	// KEM_P384_HKDF_SHA384 is a KEM using P-384 curve and HKDF with SHA-384.
	KEM_P384_HKDF_SHA384 KEM = 0x11
	// KEM_P521_HKDF_SHA512 is a KEM using P-521 curve and HKDF with SHA-512.
	KEM_P521_HKDF_SHA512 KEM = 0x12
	// KEM_X25519_HKDF_SHA256 is a KEM using X25519 Diffie-Hellman function
	// and HKDF with SHA-256.
	KEM_X25519_HKDF_SHA256 KEM = 0x20
)

func (k KEM) Scheme() kem.Scheme {
	switch k {
	case KEM_P256_HKDF_SHA256:
		return kem.DHP256HKDFSHA256()
	case KEM_P384_HKDF_SHA384:
		return kem.DHP384HKDFSHA384()
	case KEM_P521_HKDF_SHA512:
		return kem.DHP521HKDFSHA512()
	case KEM_X25519_HKDF_SHA256:
		return kem.DHX25519HKDFSHA256()
	default:
		panic("invalid kem suite")
	}
}

func (k KEM) IsValid() bool {
	switch k {
	case KEM_P256_HKDF_SHA256, KEM_P384_HKDF_SHA384, KEM_P521_HKDF_SHA512,
		KEM_X25519_HKDF_SHA256:
		return true
	default:
		return false
	}
}

// -----------------------------------------------------------------------------

type KDF uint16

//nolint:stylecheck
const (
	// KDF_HKDF_SHA256 is a KDF using HKDF with SHA-256.
	KDF_HKDF_SHA256 KDF = 0x01
	// KDF_HKDF_SHA384 is a KDF using HKDF with SHA-384.
	KDF_HKDF_SHA384 KDF = 0x02
	// KDF_HKDF_SHA512 is a KDF using HKDF with SHA-512.
	KDF_HKDF_SHA512 KDF = 0x03
)

func (k KDF) IsValid() bool {
	switch k {
	case KDF_HKDF_SHA256, KDF_HKDF_SHA384, KDF_HKDF_SHA512:
		return true
	default:
		return false
	}
}

func (k KDF) ExtractSize() uint16 {
	switch k {
	case KDF_HKDF_SHA256:
		return uint16(crypto.SHA256.Size())
	case KDF_HKDF_SHA384:
		return uint16(crypto.SHA384.Size())
	case KDF_HKDF_SHA512:
		return uint16(crypto.SHA512.Size())
	default:
		panic("invalid hash")
	}
}

func (k KDF) Extract(secret, salt []byte) []byte {
	return hkdf.Extract(k.hash(), secret, salt)
}

func (k KDF) Expand(prk, labeledInfo []byte, outputLen uint16) ([]byte, error) {
	extractSize := k.ExtractSize()
	// https://www.rfc-editor.org/rfc/rfc9180.html#kdf-input-length
	if len(prk) < int(extractSize) {
		return nil, fmt.Errorf("pseudorandom key must be at least %d bytes", extractSize)
	}
	// https://www.rfc-editor.org/rfc/rfc9180.html#name-secret-export
	if maxLength := 255 * extractSize; outputLen > maxLength {
		return nil, fmt.Errorf("expansion length is limited to %d", maxLength)
	}

	r := hkdf.Expand(k.hash(), prk, labeledInfo)
	out := make([]byte, outputLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("unable to generate value from kdf: %w", err)
	}

	return out, nil
}

func (k KDF) hash() func() hash.Hash {
	switch k {
	case KDF_HKDF_SHA256:
		return sha256.New
	case KDF_HKDF_SHA384:
		return sha512.New384
	case KDF_HKDF_SHA512:
		return sha512.New
	default:
		panic("invalid hash")
	}
}

// -----------------------------------------------------------------------------

type AEAD uint16

//nolint:stylecheck
const (
	// AEAD_AES128GCM is AES-128 block cipher in Galois Counter Mode (GCM).
	AEAD_AES128GCM AEAD = 0x01
	// AEAD_AES256GCM is AES-256 block cipher in Galois Counter Mode (GCM).
	AEAD_AES256GCM AEAD = 0x02
	// AEAD_ChaCha20Poly1305 is ChaCha20 stream cipher and Poly1305 MAC.
	AEAD_ChaCha20Poly1305 AEAD = 0x03
	// AEAD_EXPORT_ONLY is reserved for applications that only use the Exporter
	// interface.
	AEAD_EXPORT_ONLY AEAD = 0xFFFF
)

func (a AEAD) IsValid() bool {
	switch a {
	case AEAD_AES128GCM, AEAD_AES256GCM, AEAD_ChaCha20Poly1305, AEAD_EXPORT_ONLY:
		return true
	default:
		return false
	}
}

func (a AEAD) New(key []byte) (cipher.AEAD, error) {
	switch a {
	case AEAD_AES128GCM, AEAD_AES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case AEAD_ChaCha20Poly1305:
		return chacha20poly1305.New(key)
	case AEAD_EXPORT_ONLY:
		return nil, errors.New("AEAD cipher can't be initialized in export-only mode")
	default:
		panic("invalid aead")
	}
}

func (a AEAD) KeySize() uint16 {
	switch a {
	case AEAD_AES128GCM:
		return 16
	case AEAD_AES256GCM:
		return 32
	case AEAD_ChaCha20Poly1305:
		return chacha20poly1305.KeySize
	case AEAD_EXPORT_ONLY:
		return 0
	default:
		panic("invalid aead")
	}
}

func (a AEAD) NonceSize() uint16 {
	switch a {
	case AEAD_AES128GCM,
		AEAD_AES256GCM,
		AEAD_ChaCha20Poly1305:
		return 12
	case AEAD_EXPORT_ONLY:
		return 0
	default:
		panic("invalid aead")
	}
}
