package password

import (
	"errors"
	"sync"
)

var (
	// Default butcher instance
	defaultInstance Hasher
	once            sync.Once
)

// ErrNotInitialized is returned when the default instance is not initialized
var ErrNotInitialized = errors.New("default instance not initialized")

// Hash password using default instance
//
//nolint:wrapcheck
func Hash(password []byte) (string, error) {
	if defaultInstance == nil {
		return "", ErrNotInitialized
	}
	return defaultInstance.Hash(password)
}

// Verify password using default instance
//
//nolint:wrapcheck
func Verify(encoded string, password []byte) (bool, error) {
	if defaultInstance == nil {
		return false, ErrNotInitialized
	}
	return defaultInstance.Verify(encoded, password)
}

// NeedsEncodingUpgrade returns the password hash upgrade need when DefaultAlgorithm is changed
func NeedsEncodingUpgrade(encoded string) bool {
	if defaultInstance == nil {
		panic(ErrNotInitialized)
	}
	return defaultInstance.NeedsEncodingUpgrade(encoded)
}

func init() {
	once.Do(func() {
		var err error
		defaultInstance, err = New()
		if err != nil {
			panic(err)
		}
	})
}
