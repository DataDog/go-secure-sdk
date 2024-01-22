package password

import (
	"errors"

	"github.com/DataDog/go-secure-sdk/crypto/hashutil/password/internal/hasher"
)

var (
	// ErrInvalidHash is raised when caller tries to use a invalid encoded hash.
	ErrInvalidHash = errors.New("invalid hash")
	// ErrStrategyNotSupported is raised when caller tries to use a strategy which is not supported.
	ErrStrategyNotSupported = errors.New("given strategy is not supported")
)

const (
	// DefaultAlgorithm defines the default algorithm to use when not specified
	defaultAlgorithm        = hasher.Argon2id
	defaultAlgorithmVersion = uint8(0x01)

	// ExpectedAlgorithmVersion defines the lower supported version of the hashing strategy
	expectedAlgorithmVersion = uint8(0x01)
)

// DefaultSaltFunc defines the default salt generation factory to use when not specified
var defaultSaltFunc = RandomNonce(32)

// Hasher represents password hasher contract.
type Hasher interface {
	// Hash the given password with the appropriate strategy and return the
	// encoded hash.
	Hash(password []byte) (string, error)
	// Verify the encoded hash against the provided password.
	Verify(encoded string, password []byte) (bool, error)
	// NeedsEncodingUpgrade checks whether or not the provided encoded password
	// require a storage strategy upgrade.
	NeedsEncodingUpgrade(encoded string) bool
}
