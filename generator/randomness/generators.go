package randomness

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"sync"
)

var (
	ascii string
	once  sync.Once
)

// Bytes generates a new byte slice of the given size.
//
// Entropy is 8 bits per byte.
func Bytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return nil, fmt.Errorf("error generating bytes: %w", err)
	}
	return bytes, nil
}

// String returns a random string of a given length using the characters in
// the given string. It splits the string on runes to support UTF-8
// characters.
//
// Entropy is log2(len(chars)) bits per character.
func String(length int, chars string) (string, error) {
	result := make([]rune, length)
	runes := []rune(chars)
	x := int64(len(runes))
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(x))
		if err != nil {
			return "", fmt.Errorf("error creating random number: %w", err)
		}
		result[i] = runes[num.Int64()]
	}
	return string(result), nil
}

// ASCII returns a securely generated random ASCII string. It reads random
// numbers from crypto/rand and searches for printable characters. It will
// return an error if the system's secure random number generator fails to
// function correctly, in which case the caller must not continue.
//
// Entropy is 6.5 bits per character.
func ASCII(length int) (string, error) {
	once.Do(func() {
		// Initialize the characters in ASCII from 33 to 126 (94 characters)
		// https://en.wikipedia.org/wiki/ASCII#Printable_characters
		asciiBytes := make([]byte, 94)
		for i := range asciiBytes {
			asciiBytes[i] = byte(i + 33)
		}
		ascii = string(asciiBytes)
	})
	return String(length, ascii)
}

// Alphanumeric returns a random string of the given length using the 62
// alphanumeric characters in the POSIX/C locale (0-9+a-z+A-Z).
//
// Entropy is 5.95 bits per character.
func Alphanumeric(length int) (string, error) {
	return String(length, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// Alphabet returns a random string of the given length using the 52
// alphabetic characters in the POSIX/C locale (a-z+A-Z).
//
// Entropy is 5.7 bits per character.
func Alphabet(length int) (string, error) {
	return String(length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// VerificationCode returns a random string without vowels and confusing
// characters (0, O, 1, l, I). It is useful to prevent word generation and
// more precisely offensive words.
// It uses the 20 characters in the POSIX/C locale (BCDFGHJKLMNPQRSTVWXYZ).
//
// Entropy is 4.32 bits per character.
func VerificationCode(length int) (string, error) {
	return String(length, "BCDFGHJKLMNPQRSTVWXYZ")
}

// Hex returns a random string of the given length using the hexadecimal
// characters in lower case (0-9+a-f).
//
// Entropy is 4 bits per character.
func Hex(length int) (string, error) {
	return String(length, "0123456789abcdef")
}

// Number returns a random string of the given length using the 10
// numeric characters in the POSIX/C locale (0-9).
//
// Entropy is 3.32 bits per character.
func Number(length int) (string, error) {
	return String(length, "0123456789")
}
