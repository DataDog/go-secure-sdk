package password

import (
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/DataDog/go-secure-sdk/crypto/hashutil/password/internal/hasher"
)

// New hasher instance is built according options
func New(options ...Option) (Hasher, error) {
	var err error

	// Initialize default hasher
	h := defaultHasher{
		algorithm: defaultAlgorithm,
		version:   defaultAlgorithmVersion,
		saltFunc:  defaultSaltFunc,
		pepper:    nil,
	}

	// Iterates on given options
	for _, option := range options {
		option(&h)
	}

	return &h, err
}

// -----------------------------------------------------------------------------

// Hasher defines the password hasher configuration
type defaultHasher struct {
	algorithm hasher.Algorithm
	version   uint8
	saltFunc  func() []byte
	pepper    []byte
}

// Hash the given password with the hash strategy
func (b *defaultHasher) Hash(password []byte) (string, error) {
	// Resolve deriver
	deriver, ok := hasher.Strategies[b.algorithm]
	if !ok {
		return "", fmt.Errorf("unable to lookup the appropriate deriver %x: %w", b.algorithm, ErrStrategyNotSupported)
	}

	// Check supported algorithm
	strategy, ok := deriver[b.version]
	if !ok {
		return "", fmt.Errorf("unable to lookup the appropriate deriver %x in version %x: %w", b.algorithm, b.version, ErrStrategyNotSupported)
	}

	// Peppering password
	var peppered []byte
	peppered = append(peppered, password...)
	if len(b.pepper) > 0 {
		peppered = append(peppered, b.pepper...)
	}

	// Hash password
	meta, err := strategy(b.saltFunc).Hash(peppered)
	if err != nil {
		return "", fmt.Errorf("unable to hash password: %w", err)
	}

	// Return result
	encoded, err := meta.Pack()
	if err != nil {
		return "", fmt.Errorf("unable to encode the computed hash: %w", err)
	}

	return encoded, nil
}

// Verify cleartext password with encoded one
func (b *defaultHasher) Verify(encoded string, password []byte) (bool, error) {
	// Decode from string
	m, err := hasher.Decode(strings.NewReader(encoded))
	if err != nil {
		return false, ErrInvalidHash
	}

	// Check supported algorithm
	deriver, ok := hasher.Strategies[hasher.Algorithm(m.Algorithm)]
	if !ok {
		return false, ErrStrategyNotSupported
	}
	strategy, ok := deriver[m.Version]
	if !ok {
		return false, ErrStrategyNotSupported
	}

	// Peppering password
	var peppered []byte
	peppered = append(peppered, password...)
	if len(b.pepper) > 0 {
		peppered = append(peppered, b.pepper...)
	}

	// Hash given password
	pmeta, err := strategy(FixedNonce(m.Salt)).Hash(peppered)
	if err != nil {
		return false, fmt.Errorf("unable to hash given password, %v", err)
	}

	// Encode given password
	hashedPassword, err := pmeta.Pack()
	if err != nil {
		return false, fmt.Errorf("unable to encode given password, %v", err)
	}

	// Time constant compare
	return subtle.ConstantTimeCompare([]byte(encoded), []byte(hashedPassword)) == 1, nil
}

// NeedsEncodingUpgrade returns the password hash upgrade need when DefaultAlgorithm is changed
func (b *defaultHasher) NeedsEncodingUpgrade(encoded string) bool {
	// Decode from string
	m, err := hasher.Decode(strings.NewReader(encoded))
	if err != nil {
		return false
	}

	return hasher.Algorithm(m.Algorithm) != defaultAlgorithm ||
		hasher.Algorithm(m.Algorithm) == defaultAlgorithm && m.Version < expectedAlgorithmVersion
}
