package kem

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/sha512"
)

// Scheme defines the default KEM suite contract.
type Scheme interface {
	SuiteID() []byte
	GenerateKeyPair() (*ecdh.PublicKey, *ecdh.PrivateKey, error)
	DeriveKeyPair(seed []byte) (*ecdh.PublicKey, *ecdh.PrivateKey, error)
	SerializePublicKey(pkX *ecdh.PublicKey) []byte
	DeserializePublicKey(pkXxm []byte) (*ecdh.PublicKey, error)
	SerializePrivateKey(sk *ecdh.PrivateKey) []byte
	DeserializePrivateKey(skRaw []byte) (*ecdh.PrivateKey, error)
	Encapsulate(pkR *ecdh.PublicKey) (ss, enc []byte, err error)
	EncapsulateDeterministically(seed []byte, pkR *ecdh.PublicKey) (ss, enc []byte, err error)
	Decapsulate(enc []byte, skR *ecdh.PrivateKey) ([]byte, error)
	AuthEncapsulate(pkR *ecdh.PublicKey, skS *ecdh.PrivateKey) (ss, enc []byte, err error)
	AuthEncapsulateDeterministically(seed []byte, pkR *ecdh.PublicKey, skS *ecdh.PrivateKey) (ss, enc []byte, err error)
	AuthDecapsulate(enc []byte, skR *ecdh.PrivateKey, pkS *ecdh.PublicKey) ([]byte, error)
	EncapsulationSize() uint16
	PublicKeySize() uint16
	PrivateKeySize() uint16
	SecretSize() uint16
}

// DHP256HKDFSHA256 defines a KEM Suite based on P-256 curve with HKDF-SHA256
// for shared secret derivation.
func DHP256HKDFSHA256() Scheme {
	return &dhkem{
		kemID:          16,
		curve:          ecdh.P256(),
		fh:             sha256.New,
		nSecret:        32,
		nEnc:           65,
		nPk:            65,
		nSk:            32,
		keyDeriverFunc: ecDeriver(ecdh.P256()),
	}
}

// DHP384HKDFSHA384 defines a KEM Suite based on P-384 curve with HKDF-SHA384
// for shared secret derivation.
func DHP384HKDFSHA384() Scheme {
	return &dhkem{
		kemID:          17,
		curve:          ecdh.P384(),
		fh:             sha512.New384,
		nSecret:        48,
		nEnc:           97,
		nPk:            97,
		nSk:            48,
		keyDeriverFunc: ecDeriver(ecdh.P384()),
	}
}

// DHP521HKDFSHA512 defines a KEM Suite based on P-521 curve with HKDF-SHA512
// for shared secret derivation.
func DHP521HKDFSHA512() Scheme {
	return &dhkem{
		kemID:          18,
		curve:          ecdh.P521(),
		fh:             sha512.New,
		nSecret:        64,
		nEnc:           133,
		nPk:            133,
		nSk:            66,
		keyDeriverFunc: ecDeriver(ecdh.P521()),
	}
}

// DHX25519HKDFSHA256 defines a KEM Suite based on Curve25519 curve with
// HKDF-SHA256 for shared secret derivation.
func DHX25519HKDFSHA256() Scheme {
	return &dhkem{
		kemID:          32,
		curve:          ecdh.X25519(),
		fh:             sha256.New,
		nSecret:        32,
		nEnc:           32,
		nPk:            32,
		nSk:            32,
		keyDeriverFunc: xDeriver,
	}
}
