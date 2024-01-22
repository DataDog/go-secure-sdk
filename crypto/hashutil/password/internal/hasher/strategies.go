package hasher

type SaltBuilderFunc func(func() []byte) Strategy

// Strategies defines available hashing strategies
var Strategies = map[Algorithm]map[uint8]SaltBuilderFunc{
	Argon2id: {
		0x01: func(salt func() []byte) Strategy {
			return newArgon2Deriver(0x01, salt(), 4, 64*1024, 1)
		},
	},
	Pbkdf2HmacSha512: {
		0x01: func(salt func() []byte) Strategy {
			// PBKDF2-HMAC-SHA512 with 250000 iterations
			return newPbkdf2Deriver(0x01, salt(), 250000)
		},
	},
}
