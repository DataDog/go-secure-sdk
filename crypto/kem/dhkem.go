package kem

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

var (
	// ErrDeserialization is raised when the given material can't be decoded as
	// the expected key type.
	ErrDeserialization = errors.New("unable to deserialize key content")
	// ErrEncap is raised when an error occurred during shared secret encapsulation.
	ErrEncap = errors.New("unable to encapsulate the shared secret")
	// ErrDecap is raised when an error occurred during shared secret decapsulation.
	ErrDecap = errors.New("unable to decapsulate the shared secret")
)

// Implements https://www.rfc-editor.org/rfc/rfc9180.html#name-dh-based-kem-dhkem
type dhkem struct {
	kemID          uint16
	curve          ecdh.Curve
	fh             func() hash.Hash
	nSecret        uint16
	nEnc           uint16
	nPk            uint16
	nSk            uint16
	keyDeriverFunc keyDeriver
}

// SuiteID returns the public suite identifier used for material derivation.
func (kem *dhkem) SuiteID() []byte {
	var out [5]byte
	// suite_id = concat("KEM", I2OSP(kem_id, 2))
	out[0], out[1], out[2] = 'K', 'E', 'M'
	binary.BigEndian.PutUint16(out[3:5], kem.kemID)
	return out[:]
}

// PublicKeySize returns the serialized public key size.
func (kem *dhkem) PublicKeySize() uint16 {
	return kem.nPk
}

// PrivateKeySize returns the serialized private key size.
func (kem *dhkem) PrivateKeySize() uint16 {
	return kem.nSk
}

// EncapsulationSize returns the encapsulation size.
func (kem *dhkem) EncapsulationSize() uint16 {
	return kem.nEnc
}

// SecretSize returns the shared secret size.
func (kem *dhkem) SecretSize() uint16 {
	return kem.nSecret
}

// DeriveKeyPair generates deterministically according to the seed content a
// keypair.
func (kem *dhkem) DeriveKeyPair(seed []byte) (*ecdh.PublicKey, *ecdh.PrivateKey, error) {
	return kem.keyDeriverFunc(kem, seed)
}

// GenerateKeyPair generates a key associated to the suite.
func (kem *dhkem) GenerateKeyPair() (*ecdh.PublicKey, *ecdh.PrivateKey, error) {
	sk, err := kem.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate key pair from the suite: %w", err)
	}

	return sk.PublicKey(), sk, nil
}

// SerializePublicKey exports the given public key as a byte array.
func (kem *dhkem) SerializePublicKey(pkX *ecdh.PublicKey) []byte {
	raw := pkX.Bytes()
	if len(raw) != int(kem.nPk) {
		panic("invalid public key size")
	}

	return raw
}

// DeserializePublicKey reads the given content and try to extract a public key
// matching the suite public key type.
func (kem *dhkem) DeserializePublicKey(pkXxm []byte) (*ecdh.PublicKey, error) {
	if len(pkXxm) != int(kem.nPk) {
		return nil, errors.New("public key data size is invalid")
	}

	return kem.curve.NewPublicKey(pkXxm)
}

// SerializePrivateKey exports the given private key as a byte array.
func (kem *dhkem) SerializePrivateKey(sk *ecdh.PrivateKey) []byte {
	raw := sk.Bytes()
	if len(raw) != int(kem.nSk) {
		panic("invalid private key size")
	}

	return raw
}

// DeserializePrivateKey reads the given content and try to extract a private key
// matching the suite private key type.
func (kem *dhkem) DeserializePrivateKey(raw []byte) (*ecdh.PrivateKey, error) {
	if len(raw) != int(kem.nSk) {
		return nil, errors.New("private key data size is invalid")
	}

	return kem.curve.NewPrivateKey(raw)
}

// EncapsulateDeterministically computes the shared secret and exports a deterministic
// encapsulated public key based on a remote static public key and the given seed.
//
// If you don't which encapsulation you should choose, consider using `Encapsulate`
// function.
func (kem *dhkem) EncapsulateDeterministically(seed []byte, pkR *ecdh.PublicKey) (ss, enc []byte, err error) {
	if len(seed) != int(kem.nSk) {
		return nil, nil, fmt.Errorf("seed is too short, got %d, expected %d", len(seed), kem.nSk)
	}

	// skE, pkE = DeriveKeyPair()
	pkE, skE, err := kem.DeriveKeyPair(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate ephemeral keypair: %v: %w", err, ErrEncap)
	}

	return kem.encapsulate(pkE, skE, pkR)
}

// Encapsulate computes the shared secret and exports encapsulated public key
// based on a remote static public key.
func (kem *dhkem) Encapsulate(pkR *ecdh.PublicKey) (ss, enc []byte, err error) {
	// skE, pkE = GenerateKeyPair()
	pkE, skE, err := kem.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate ephemeral keypair: %v: %w", err, ErrEncap)
	}

	return kem.encapsulate(pkE, skE, pkR)
}

func (kem *dhkem) encapsulate(pkE *ecdh.PublicKey, skE *ecdh.PrivateKey, pkR *ecdh.PublicKey) (ss, enc []byte, err error) {
	// dh = DH(skE, pkR)
	dh, err := skE.ECDH(pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to compute key agreement: %v: %w", err, ErrEncap)
	}
	defer kem.wipeBytes(dh)

	enc = kem.SerializePublicKey(pkE)
	if len(enc) != int(kem.nEnc) {
		return nil, nil, errors.New("invalid encapsulation size")
	}
	pkRm := kem.SerializePublicKey(pkR)

	// kem_context = concat(enc, pkRm)
	kemContext := append([]byte{}, enc...)
	kemContext = append(kemContext, pkRm...)
	ssRaw, err := kem.extractAndExpand(dh, kemContext)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to compute shared secret: %v: %w", err, ErrEncap)
	}

	return ssRaw, enc, nil
}

// Decapsulate computes the shared secret from the given encapsulated public key
// and a receiver static public key.
func (kem *dhkem) Decapsulate(enc []byte, skR *ecdh.PrivateKey) ([]byte, error) {
	if len(enc) != int(kem.nEnc) {
		return nil, fmt.Errorf("invalid encapsulation size: %w", ErrDecap)
	}

	// Copy encapsulated data
	localEnc := make([]byte, kem.nEnc)
	copy(localEnc, enc)

	// Try to deserialize received public key.
	pkE, err := kem.DeserializePublicKey(localEnc)
	if err != nil {
		return nil, fmt.Errorf("unable to deserialize public key: %v: %w", err, ErrDecap)
	}

	// dh = DH(skR, pkE)
	dh, err := skR.ECDH(pkE)
	if err != nil {
		return nil, fmt.Errorf("unable to compute key agreement: %v: %w", err, ErrDecap)
	}
	defer kem.wipeBytes(dh)

	pkRm := kem.SerializePublicKey(skR.PublicKey())

	// kem_context = concat(enc, pkRm)
	kemContext := append([]byte{}, localEnc...)
	kemContext = append(kemContext, pkRm...)

	// shared_secret = ExtractAndExpand(dh, kem_context)
	ssRaw, err := kem.extractAndExpand(dh, kemContext)
	if err != nil {
		return nil, fmt.Errorf("unable to compute shared secret: %v: %w", err, ErrDecap)
	}

	return ssRaw, nil
}

// AuthEncapsulateDeterministically computes a shared secret, and an deterministic
// encapsulated public key based on mutual sender and receiver static keys authentication
// and the given seed.
//
// If you don't which encapsulation you should choose, consider using `AuthEncapsulate`
// function.
func (kem *dhkem) AuthEncapsulateDeterministically(seed []byte, pkR *ecdh.PublicKey, skS *ecdh.PrivateKey) (ss, enc []byte, err error) {
	if len(seed) != int(kem.nSk) {
		return nil, nil, fmt.Errorf("seed is too short, got %d, expected %d", len(seed), kem.nSk)
	}

	// skE, pkE = DeriveKeyPair()
	pkE, skE, err := kem.DeriveKeyPair(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate ephemeral keypair: %v: %w", err, ErrEncap)
	}

	return kem.authEncapsulate(pkE, skE, pkR, skS)
}

// Encapsulate computes the shared secret and exports encapsulated public key
// based on a remote static public key.
func (kem *dhkem) AuthEncapsulate(pkR *ecdh.PublicKey, skS *ecdh.PrivateKey) (ss, enc []byte, err error) {
	// skE, pkE = GenerateKeyPair()
	pkE, skE, err := kem.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate ephemeral keypair: %v: %w", err, ErrEncap)
	}

	return kem.authEncapsulate(pkE, skE, pkR, skS)
}

// AuthEncapsulate computes a shared secret, and an encapsulated public key
// based on mutual sender and receiver static keys authentication.
func (kem *dhkem) authEncapsulate(pkE *ecdh.PublicKey, skE *ecdh.PrivateKey, pkR *ecdh.PublicKey, skS *ecdh.PrivateKey) (ss, enc []byte, err error) {
	Ze, err := skE.ECDH(pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to copute ephemeral key agreement: %w", err)
	}
	defer kem.wipeBytes(Ze)

	Zs, err := skS.ECDH(pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to compute static key agreement: %w", err)
	}
	defer kem.wipeBytes(Zs)

	// dh = concat(DH(skE, pkR), DH(skS, pkR))
	dh := append([]byte{}, Ze...)
	dh = append(dh, Zs...)
	defer kem.wipeBytes(dh)

	enc = kem.SerializePublicKey(pkE)
	pkRm := kem.SerializePublicKey(pkR)
	pkSm := kem.SerializePublicKey(skS.PublicKey())

	// kem_context = concat(enc, pkRm)
	kemContext := append([]byte{}, enc...)
	kemContext = append(kemContext, pkRm...)
	kemContext = append(kemContext, pkSm...)

	// shared_secret = ExtractAndExpand(dh, kem_context)
	ssRaw, err := kem.extractAndExpand(dh, kemContext)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to compute shared secret: %w", err)
	}

	return ssRaw, enc, nil
}

// AuthDecapsulate computes a shared secret from a received encapsulated public
// key based on mutual sender and receiver static keys authentication.
func (kem *dhkem) AuthDecapsulate(enc []byte, skR *ecdh.PrivateKey, pkS *ecdh.PublicKey) ([]byte, error) {
	if len(enc) != int(kem.nEnc) {
		return nil, errors.New("invalid encapsulation size")
	}

	// Copy encapsulated data
	localEnc := make([]byte, kem.nEnc)
	copy(localEnc, enc)

	// Try to deserialize received public key.
	pkE, err := kem.DeserializePublicKey(localEnc)
	if err != nil {
		return nil, fmt.Errorf("unable to deserialize public key: %w", err)
	}

	Ze, err := skR.ECDH(pkE)
	if err != nil {
		return nil, fmt.Errorf("unable to compute ephemeral key agreement: %w", err)
	}
	defer kem.wipeBytes(Ze)

	Zs, err := skR.ECDH(pkS)
	if err != nil {
		return nil, fmt.Errorf("unable to compute static key agreement: %w", err)
	}
	defer kem.wipeBytes(Zs)

	// dh = concat(DH(skR, pkE), DH(skR, pkS))
	dh := append([]byte{}, Ze...)
	dh = append(dh, Zs...)
	defer kem.wipeBytes(dh)

	enc = kem.SerializePublicKey(pkE)
	pkRm := kem.SerializePublicKey(skR.PublicKey())
	pkSm := kem.SerializePublicKey(pkS)

	// kem_context = concat(enc, pkRm, pkSm)
	kemContext := append([]byte{}, enc...)
	kemContext = append(kemContext, pkRm...)
	kemContext = append(kemContext, pkSm...)

	// shared_secret = ExtractAndExpand(dh, kem_context)
	ssRaw, err := kem.extractAndExpand(dh, kemContext)
	if err != nil {
		return nil, fmt.Errorf("unable to compute shared secret: %w", err)
	}

	return ssRaw, nil
}

// -----------------------------------------------------------------------------

func (kem *dhkem) extractAndExpand(dh, kemContext []byte) ([]byte, error) {
	eaePrk := kem.labeledExtract([]byte(""), []byte("eae_prk"), dh)
	return kem.labeledExpand(eaePrk, []byte("shared_secret"), kemContext, kem.nSecret)
}

func (kem *dhkem) labeledExtract(salt, label, ikm []byte) []byte {
	// labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
	labeledIKM := append([]byte("HPKE-v1"), kem.SuiteID()...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)

	return hkdf.Extract(kem.fh, labeledIKM, salt)
}

func (kem *dhkem) labeledExpand(prk, label, info []byte, outputLen uint16) ([]byte, error) {
	labeledInfo := make([]byte, 2, 2+7+5+len(label)+len(info))
	// labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
	binary.BigEndian.PutUint16(labeledInfo[0:2], outputLen)
	labeledInfo = append(labeledInfo, []byte("HPKE-v1")...)
	labeledInfo = append(labeledInfo, kem.SuiteID()...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)

	r := hkdf.Expand(kem.fh, prk, labeledInfo)
	out := make([]byte, outputLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("unable to generate secret from prf: %w", err)
	}

	return out, nil
}

func (kem *dhkem) wipeBytes(buf []byte) {
	// clear(buf) - Go 1.21
	for i := range buf {
		buf[i] = 0
	}
}
