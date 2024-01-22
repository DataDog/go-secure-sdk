package masking

import (
	"errors"
	"strings"
)

// ReserveMargin keeps only n first and last characters from the input string
// and mask others with the given mask character.
func ReserveMargin(value string, n int, mask string) (ret string, err error) {
	// Check arguments
	if value == "" {
		return "", nil
	}
	if mask == "" {
		mask = "*"
	}
	if n < 0 {
		return "", errors.New("margin must be strictly positive")
	}

	// Use rune to iterate on the input string
	runes := []rune(value)
	l := len(runes)

	// If the mask is not larger than the value length
	if 2*n < l {
		// Apply masking
		ret = string(runes[:n]) + strings.Repeat(mask, l-2*n) + string(runes[l-n:])
	} else {
		// Replace the complete value
		ret = strings.Repeat(mask, l)
	}

	return ret, err
}

// ReserveLeft keeps only n first characters from the input string and mask
// others with the given mask character.
func ReserveLeft(value string, n int, mask string) (ret string, err error) {
	// Check arguments
	if value == "" {
		return "", nil
	}
	if mask == "" {
		mask = "*"
	}
	if n < 0 {
		return "", errors.New("margin must be strictly positive")
	}

	// Use rune to iterate on the input string
	runes := []rune(value)
	l := len(runes)

	// If mask is not larger than the string length
	if n < l {
		ret = string(runes[:n]) + strings.Repeat(mask, l-n)
	}

	return ret, err
}

// ReserveRight keeps only n last characters from the input string and mask
// others with the given mask character.
func ReserveRight(value string, n int, mask string) (ret string, err error) {
	// Check arguments
	if value == "" {
		return "", nil
	}
	if mask == "" {
		mask = "*"
	}
	if n < 0 {
		return "", errors.New("margin must be strictly positive")
	}

	// Use rune to iterate on the input string
	runes := []rune(value)
	l := len(runes)

	// If mask is not larger than the string length
	if n < l {
		ret = strings.Repeat(mask, l-n) + string(runes[l-n:])
	}

	return ret, err
}
