package fpe

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/DataDog/go-secure-sdk/privacy/encryption/fpe/ff3"
)

// Regex pattern applied encryption. This function is used to encrypt part of a string using FF3-1
// encryption algorithm.
func Regex(key, tweak []byte, value, pattern, alphabet string, operation Operation) (string, error) {
	// Check arguments
	if pattern == "" {
		return "", errors.New("replacement pattern must not be blank")
	}

	// Complie replacement regex
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("unable to compile pattern expression: %w", err)
	}

	// Ensure that the value match the pattern
	if !re.MatchString(value) {
		return "", fmt.Errorf("unable to match given value with replacement pattern: %w", err)
	}
	if re.NumSubexp() < 1 {
		return "", errors.New("the pattern must define atleast one group")
	}

	// Extract all match groups
	parts := re.FindStringSubmatch(value)
	if len(parts) == 0 {
		return "", errors.New("unable to extract match groups")
	}
	indexes := re.FindStringSubmatchIndex(value)
	if len(indexes) == 0 {
		return "", errors.New("unable to extract match groups indexes")
	}

	// Initialize FF3-1
	ff3r1, err := ff3.NewFF3_1(key, tweak, alphabet)
	if err != nil {
		return "", fmt.Errorf("unable to initialize the encryption engine: %w", err)
	}

	raw := []byte(value)
	for i, p := range parts {
		if i == 0 {
			// Skip full string
			continue
		}

		// Retrieve match group indexes
		start := indexes[2*i]
		end := indexes[2*i+1]

		// Sanity check
		if p != value[start:end] {
			return "", errors.New("invalid match group value")
		}

		var (
			out          string
			errOperation error
		)
		switch operation {
		case Encrypt:
			out, errOperation = ff3r1.Encrypt(p, nil)
		case Decrypt:
			out, errOperation = ff3r1.Decrypt(p, nil)
		default:
			return "", fmt.Errorf("unsupported operation")
		}
		if errOperation != nil {
			return "", fmt.Errorf("unable to successfully apply the requested operation: %w", errOperation)
		}

		// Replace by encrypted values
		for j := range out {
			raw[start+j] = out[j]
		}
	}

	return string(raw), nil
}
