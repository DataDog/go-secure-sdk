// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package randomness

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBytes(t *testing.T) {
	t.Parallel()
	sizes := []int{4, 8, 16, 32, 64, 128}
	for _, size := range sizes {
		a, err := Bytes(size)
		assert.NoError(t, err)
		b, err := Bytes(size)
		assert.NoError(t, err)
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}

func TestString(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompilePOSIX(`^[0-9世界ñçàèìòù]+$`)
	chars := "0123456789世界ñçàèìòù"
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := String(l, chars)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := String(l, chars)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}

func TestHex(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompilePOSIX(`^[0-9a-f]+$`)
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := Hex(l)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := Hex(l)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}

func TestAlphanumeric(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompilePOSIX(`^[0-9a-zA-Z]+$`)
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := Alphanumeric(l)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := Alphanumeric(l)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}

func TestASCII(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompilePOSIX("^[\x21-\x7E]+$")
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := ASCII(l)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := ASCII(l)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}

func TestAlphabet(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompilePOSIX(`^[a-zA-Z]+$`)
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := Alphabet(l)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := Alphabet(l)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}

func TestVerificationCode(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompilePOSIX(`^[BCDFGHJKLMNPQRSTVWXYZ]+$`)
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := VerificationCode(l)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := VerificationCode(l)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}

func TestNumber(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompilePOSIX(`^[0-9]+$`)
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := Number(l)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := Number(l)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}
