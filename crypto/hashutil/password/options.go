package password

import "github.com/DataDog/go-secure-sdk/crypto/hashutil/password/internal/hasher"

// Option is the hasher option setting function signature
type Option func(*defaultHasher)

// WithSaltFunc defines the salt factory value for salt generation
func WithSaltFunc(factory func() []byte) Option {
	return func(dh *defaultHasher) {
		dh.saltFunc = factory
	}
}

// WithFIPSCompliance enables FIPS-140-2 password hashing
func WithFIPSCompliance() Option {
	return func(dh *defaultHasher) {
		dh.algorithm = hasher.Pbkdf2HmacSha512
		dh.version = 0x01
	}
}

// WithPepper defines the password peppering value
func WithPepper(value []byte) Option {
	return func(dh *defaultHasher) {
		dh.pepper = value
	}
}
