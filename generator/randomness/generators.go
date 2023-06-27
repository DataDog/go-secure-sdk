// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package randomness

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

// initialize the ASCII characters
var ascii = func() string {
	asciiBytes := make([]byte, 94)
	for i := range asciiBytes {
		asciiBytes[i] = byte(i + 33)
	}
	return string(asciiBytes)
}()

// Bytes generates a new byte slice of the given size.
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

// Hex returns a random string of the given length using the hexadecimal
// characters in lower case (0-9+a-f).
func Hex(length int) (string, error) {
	return String(length, "0123456789abcdef")
}

// Alphanumeric returns a random string of the given length using the 62
// alphanumeric characters in the POSIX/C locale (a-z+A-Z+0-9).
func Alphanumeric(length int) (string, error) {
	return String(length, "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// ASCII returns a securely generated random ASCII string. It reads random
// numbers from crypto/rand and searches for printable characters. It will
// return an error if the system's secure random number generator fails to
// function correctly, in which case the caller must not continue.
func ASCII(length int) (string, error) {
	return String(length, ascii)
}

// Alphabet returns a random string of the given length using the 52
// alphabetic characters in the POSIX/C locale (a-z+A-Z).
func Alphabet(length int) (string, error) {
	return String(length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}
