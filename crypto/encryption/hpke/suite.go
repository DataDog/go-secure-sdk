package hpke

import (
	"crypto/ecdh"
	"encoding/binary"

	"github.com/DataDog/go-secure-sdk/crypto/kem"
)

// Suite repesents a HPKE cipher suite contract.
type Suite interface {
	IsValid() bool
	Params() (KEM, KDF, AEAD)
	KEM() kem.Scheme
	Sender(pkR *ecdh.PublicKey, info []byte) Sender
	Receiver(skR *ecdh.PrivateKey, info []byte) Receiver
}

// New initializes a new HPKE suite.
func New(kemID KEM, kdfID KDF, aeadID AEAD) Suite {
	return &cipherSuite{
		kemID:  kemID,
		kdfID:  kdfID,
		aeadID: aeadID,
	}
}

// Suite represents HPKE suite parameters.
type cipherSuite struct {
	kemID  KEM
	kdfID  KDF
	aeadID AEAD
}

// IsValid checks if the suite is initialized with valid values.
func (s *cipherSuite) IsValid() bool {
	return s.kemID.IsValid() && s.kdfID.IsValid() && s.aeadID.IsValid()
}

// KEM returns the associated KEM algorithm.
func (s *cipherSuite) KEM() kem.Scheme {
	return s.kemID.Scheme()
}

// SuiteID returns the public suite identifier used for material derivation.
func (s *cipherSuite) suiteID() []byte {
	var out [10]byte
	// suite_id = concat("HPKE", I2OSP(kem_id, 2), ISOSP(kdf_id, 2), ISOSP(aead_id, 2))
	out[0], out[1], out[2], out[3] = 'H', 'P', 'K', 'E'
	binary.BigEndian.PutUint16(out[4:6], uint16(s.kemID))
	binary.BigEndian.PutUint16(out[6:8], uint16(s.kdfID))
	binary.BigEndian.PutUint16(out[8:10], uint16(s.aeadID))
	return out[:]
}

// Params returns suite parameters.
func (s *cipherSuite) Params() (KEM, KDF, AEAD) {
	return s.kemID, s.kdfID, s.aeadID
}

// Sender returns a message sender context builder.
func (s *cipherSuite) Sender(pkR *ecdh.PublicKey, info []byte) Sender {
	return &sender{
		cipherSuite: s,
		pkR:         pkR,
		info:        info,
	}
}

// Receiver returns a message receiver context builder.
func (s *cipherSuite) Receiver(skR *ecdh.PrivateKey, info []byte) Receiver {
	return &receiver{
		cipherSuite: s,
		skR:         skR,
		info:        info,
	}
}

// -----------------------------------------------------------------------------

func (s *cipherSuite) labeledExtract(salt, label, ikm []byte) []byte {
	// labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
	labeledIKM := append([]byte("HPKE-v1"), s.suiteID()...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)

	return s.kdfID.Extract(labeledIKM, salt)
}

func (s *cipherSuite) labeledExpand(prk, label, info []byte, outputLen uint16) ([]byte, error) {
	labeledInfo := make([]byte, 2, 2+7+10+len(label)+len(info))
	// labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
	binary.BigEndian.PutUint16(labeledInfo[0:2], outputLen)
	labeledInfo = append(labeledInfo, []byte("HPKE-v1")...)
	labeledInfo = append(labeledInfo, s.suiteID()...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)

	return s.kdfID.Expand(prk, labeledInfo, outputLen)
}
