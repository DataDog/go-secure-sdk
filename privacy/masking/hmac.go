package masking

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/DataDog/go-secure-sdk/generator/randomness"

	"golang.org/x/crypto/hkdf"
)

// HMAC generates a HMAC-SHA256 hex encoded output of the given value.
//
// The output is deterministic.
func HMAC(value string, key []byte) (string, error) {
	// Check arguments
	if len(key) < sha256.Size {
		return "", errors.New("the key must be at least a 32bytes length array")
	}

	h := hmac.New(sha256.New, key)
	h.Write([]byte("datadog-privacy-masking-hmac0-v1"))
	h.Write([]byte(value))

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// NonDeterministicHMAC generates a HKDF-SHA256 hex encoded output of the given
// value. By being non-deterministic, it breaks the linkability between encoded
// values, but stays verifiable from the original value computation.
//
// The output is NON deterministic.
func NonDeterministicHMAC(value string, key []byte) (string, error) {
	// Check arguments
	if len(key) < sha256.Size {
		return "", errors.New("the key must be at least a 32bytes length array")
	}

	// Generate a salt (96bits)
	salt, err := randomness.Bytes(8)
	if err != nil {
		return "", fmt.Errorf("unable to generate random salt: %w", err)
	}

	// salt (8B) || hash (32B)
	out := make([]byte, 40)
	r := hkdf.New(sha256.New, key, salt, []byte("datadog-privacy-masking-hkdf0-v1"))
	copy(out, salt)
	if _, err := r.Read(out[8:]); err != nil {
		return "", fmt.Errorf("unable to read derived mask value: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(out), nil
}
