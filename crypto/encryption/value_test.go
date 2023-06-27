// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package encryption

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	security "github.com/DataDog/go-secure-sdk"
	"github.com/DataDog/go-secure-sdk/crypto/canonicalization"
	"github.com/DataDog/go-secure-sdk/crypto/encryption/internal/d1"
	"github.com/DataDog/go-secure-sdk/crypto/encryption/internal/d2"
)

func TestValue(t *testing.T) {
	t.Parallel()

	t.Run("Key too large", func(t *testing.T) {
		t.Parallel()

		f, err := Value(bytes.Repeat([]byte("A"), maximumKeyLength+1))
		require.Error(t, err)
		require.Nil(t, f)
	})

	t.Run("Seal/Open", func(t *testing.T) {
		t.Parallel()

		f, err := Value([]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
		require.NoError(t, err)
		require.NotNil(t, f)

		msg := []byte("Hello World!")

		ciphertext, err := f.Seal(msg)
		require.NoError(t, err)
		require.NotNil(t, ciphertext)

		out, err := f.Open(ciphertext)
		require.NoError(t, err)
		require.Equal(t, msg, out)
	})

	t.Run("Seal/Open WithContext", func(t *testing.T) {
		t.Parallel()

		f, err := Value([]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
		require.NoError(t, err)
		require.NotNil(t, f)

		msg := []byte("Hello World!")

		ciphertext, err := f.SealWithContext(msg, []byte(`{uid:"12345"}`))
		require.NoError(t, err)
		require.NotNil(t, ciphertext)

		out, err := f.OpenWithContext(ciphertext, []byte(`{uid:"12345"}`))
		require.NoError(t, err)
		require.Equal(t, msg, out)
	})

	t.Run("Seal/Open WithContext mismatch", func(t *testing.T) {
		t.Parallel()

		f, err := Value([]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
		require.NoError(t, err)
		require.NotNil(t, f)

		msg := []byte("Hello World!")

		ciphertext, err := f.SealWithContext(msg, []byte(`{uid:"12345"}`))
		require.NoError(t, err)
		require.NotNil(t, ciphertext)

		out, err := f.OpenWithContext(ciphertext, []byte(`{uid:"987654"}`))
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("Seal WithContext error", func(t *testing.T) {
		t.Parallel()

		f, err := Value([]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
		require.NoError(t, err)
		require.NotNil(t, f)

		msg := []byte("Hello World!")
		tooLarge := bytes.Repeat([]byte{0x41}, 65*1024) // 65Kb piece

		ciphertext, err := f.SealWithContext(msg, tooLarge)
		require.Error(t, err)
		require.ErrorIs(t, err, canonicalization.ErrPieceTooLarge)
		require.Nil(t, ciphertext)
	})

	t.Run("Open WithContext error", func(t *testing.T) {
		t.Parallel()

		f, err := Value([]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
		require.NoError(t, err)
		require.NotNil(t, f)

		msg := []byte("Hello World!")
		tooLarge := bytes.Repeat([]byte{0x41}, 65*1024) // 65Kb piece

		ciphertext, err := f.SealWithContext(msg, []byte(`{uid:"12345"}`))
		require.NoError(t, err)
		require.NotNil(t, ciphertext)

		out, err := f.OpenWithContext(ciphertext, tooLarge)
		require.Error(t, err)
		require.ErrorIs(t, err, canonicalization.ErrPieceTooLarge)
		require.Nil(t, out)
	})
}

func TestValueWithMode(t *testing.T) {
	t.Parallel()

	t.Run("invalid mode", func(t *testing.T) {
		t.Parallel()

		f, err := ValueWithMode(99, []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
		require.Error(t, err)
		require.Nil(t, f)
	})

	t.Run("FIPS cipher", func(t *testing.T) {
		t.Parallel()

		t.Run("Seal/Open", func(t *testing.T) {
			t.Parallel()

			f, err := ValueWithMode(FIPS, []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
			require.NoError(t, err)
			require.NotNil(t, f)
			require.Equal(t, uint8(d1.MagicVersion), f.CipherID())

			msg := []byte("Hello World!")

			ciphertext, err := f.Seal(msg)
			require.NoError(t, err)
			require.NotNil(t, ciphertext)

			out, err := f.Open(ciphertext)
			require.NoError(t, err)
			require.Equal(t, msg, out)
		})

		t.Run("Seal/Open WithContext", func(t *testing.T) {
			t.Parallel()

			f, err := ValueWithMode(FIPS, []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
			require.NoError(t, err)
			require.NotNil(t, f)

			msg := []byte("Hello World!")

			ciphertext, err := f.SealWithContext(msg, []byte(`{uid:"12345"}`))
			require.NoError(t, err)
			require.NotNil(t, ciphertext)

			out, err := f.OpenWithContext(ciphertext, []byte(`{uid:"12345"}`))
			require.NoError(t, err)
			require.Equal(t, msg, out)
		})
	})

	t.Run("Modern cipher", func(t *testing.T) {
		t.Parallel()

		t.Run("Seal/Open", func(t *testing.T) {
			t.Parallel()

			f, err := ValueWithMode(Modern, []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
			require.NoError(t, err)
			require.NotNil(t, f)
			require.Equal(t, uint8(d2.MagicVersion), f.CipherID())

			msg := []byte("Hello World!")

			ciphertext, err := f.Seal(msg)
			require.NoError(t, err)
			require.NotNil(t, ciphertext)

			out, err := f.Open(ciphertext)
			require.NoError(t, err)
			require.Equal(t, msg, out)
		})

		t.Run("Seal/Open WithContext", func(t *testing.T) {
			t.Parallel()

			f, err := ValueWithMode(Modern, []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
			require.NoError(t, err)
			require.NotNil(t, f)

			msg := []byte("Hello World!")

			ciphertext, err := f.SealWithContext(msg, []byte(`{uid:"12345"}`))
			require.NoError(t, err)
			require.NotNil(t, ciphertext)

			out, err := f.OpenWithContext(ciphertext, []byte(`{uid:"12345"}`))
			require.NoError(t, err)
			require.Equal(t, msg, out)
		})
	})
}

//nolint:paralleltest // Disable parallel testing due to the stateful nature of the FIPS flag
func TestFIPSMode(t *testing.T) {
	revertFunc := security.SetFIPSMode()
	require.True(t, security.InFIPSMode())

	// Default to FIPS cipher
	aead, err := Value([]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
	require.NoError(t, err)
	require.NotNil(t, aead)
	require.Equal(t, uint8(d1.MagicVersion), aead.CipherID())

	// Ensure that FIPS ccipher can be built directly.
	aead, err = ValueWithMode(FIPS, []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
	require.NoError(t, err)
	require.NotNil(t, aead)
	require.Equal(t, uint8(d1.MagicVersion), aead.CipherID())

	// Ensure that Modern cipher can't be built directly
	aead, err = ValueWithMode(Modern, []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
	require.Error(t, err)
	require.Nil(t, aead)

	// Disable FIPS mode -------------------------------------------------------
	revertFunc()

	// Default to Modern cipher
	aead, err = Value([]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
	require.NoError(t, err)
	require.NotNil(t, aead)
	require.Equal(t, uint8(d2.MagicVersion), aead.CipherID())

	// Ensure that Modern can be built directly
	aead, err = ValueWithMode(Modern, []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
	require.NoError(t, err)
	require.NotNil(t, aead)
	require.Equal(t, uint8(d2.MagicVersion), aead.CipherID())
}
