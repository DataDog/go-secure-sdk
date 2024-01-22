package hasher

import (
	"crypto/sha512"
	"errors"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

type pbkdf2Deriver struct {
	version    uint8
	h          func() hash.Hash
	salt       []byte
	iterations uint32
	keylen     uint32
}

func newPbkdf2Deriver(version uint8, salt []byte, iterations uint32) Strategy {
	c := &pbkdf2Deriver{
		version:    version,
		h:          sha512.New,
		salt:       salt,
		iterations: iterations,
		keylen:     kdfOutputLen,
	}
	return c
}

// -----------------------------------------------------------------------------

func (d *pbkdf2Deriver) Hash(password []byte) (*Metadata, error) {
	// Check arguments
	if d == nil {
		return nil, errors.New("unable to use this deriver with a nil instance")
	}
	if d.h == nil {
		return nil, errors.New("hash function must not be nil")
	}

	return &Metadata{
		Algorithm: uint8(Pbkdf2HmacSha512),
		Version:   d.version,
		Salt:      d.salt,
		Hash:      pbkdf2.Key(password, d.salt, int(d.iterations), int(d.keylen), d.h),
	}, nil
}
