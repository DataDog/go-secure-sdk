package hasher

import "golang.org/x/crypto/argon2"

type argonDeriver struct {
	version uint8
	salt    []byte
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

func newArgon2Deriver(version uint8, salt []byte, time, memory uint32, threads uint8) Strategy {
	return &argonDeriver{
		version: version,
		salt:    salt,
		time:    time,
		memory:  memory,
		threads: threads,
		keyLen:  kdfOutputLen,
	}
}

// -----------------------------------------------------------------------------

func (d *argonDeriver) Hash(password []byte) (*Metadata, error) {
	hash := argon2.IDKey(password, d.salt, d.time, d.memory, d.threads, d.keyLen)

	return &Metadata{
		Algorithm: uint8(Argon2id),
		Version:   d.version,
		Salt:      d.salt,
		Hash:      hash,
	}, nil
}
