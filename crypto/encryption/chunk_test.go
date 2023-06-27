// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package encryption

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/crypto/canonicalization"
	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

func TestChunked(t *testing.T) {
	t.Parallel()

	msg := &bytes.Buffer{}
	_, err := io.Copy(msg, io.LimitReader(randomness.NewReader(1), 1<<20))
	require.NoError(t, err)

	t.Run("Key too large", func(t *testing.T) {
		t.Parallel()

		f, err := Chunked(bytes.Repeat([]byte("A"), maximumKeyLength+1))
		require.Error(t, err)
		require.Nil(t, f)
	})

	t.Run("Seal/Open", func(t *testing.T) {
		t.Parallel()

		f, err := Chunked([]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
		require.NoError(t, err)
		require.NotNil(t, f)

		ciphertext := &bytes.Buffer{}
		require.NoError(t, f.Seal(ciphertext, bytes.NewReader(msg.Bytes())))

		plaintext := &bytes.Buffer{}
		require.NoError(t, f.Open(plaintext, ciphertext))

		require.Equal(t, msg.Bytes(), plaintext.Bytes())
	})

	t.Run("Seal/Open WithContext", func(t *testing.T) {
		t.Parallel()

		f, err := Chunked([]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
		require.NoError(t, err)
		require.NotNil(t, f)

		ciphertext := &bytes.Buffer{}
		require.NoError(t, f.SealWithContext(ciphertext, bytes.NewReader(msg.Bytes()), []byte(`{uid:"12345"}`)))

		plaintext := &bytes.Buffer{}
		require.NoError(t, f.OpenWithContext(plaintext, ciphertext, []byte(`{uid:"12345"}`)))

		require.Equal(t, msg.Bytes(), plaintext.Bytes())
	})

	t.Run("Seal/Open WithContext mismatch", func(t *testing.T) {
		t.Parallel()

		f, err := Chunked([]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
		require.NoError(t, err)
		require.NotNil(t, f)

		ciphertext := &bytes.Buffer{}
		require.NoError(t, f.SealWithContext(ciphertext, bytes.NewReader(msg.Bytes()), []byte(`{uid:"12345"}`)))

		plaintext := &bytes.Buffer{}
		require.Error(t, f.OpenWithContext(plaintext, ciphertext, []byte(`{uid:"98765"}`)))
	})

	t.Run("Seal WithContext error", func(t *testing.T) {
		t.Parallel()

		f, err := Chunked([]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
		require.NoError(t, err)
		require.NotNil(t, f)

		tooLarge := bytes.Repeat([]byte{0x41}, 65*1024) // 65Kb piece

		ciphertext := &bytes.Buffer{}
		err = f.SealWithContext(ciphertext, msg, tooLarge)
		require.Error(t, err)
		require.ErrorIs(t, err, canonicalization.ErrPieceTooLarge)
	})

	t.Run("Open WithContext error", func(t *testing.T) {
		t.Parallel()

		f, err := Chunked([]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"))
		require.NoError(t, err)
		require.NotNil(t, f)

		tooLarge := bytes.Repeat([]byte{0x41}, 65*1024) // 65Kb piece

		ciphertext := &bytes.Buffer{}
		require.NoError(t, f.SealWithContext(ciphertext, bytes.NewReader(msg.Bytes()), []byte(`{uid:"12345"}`)))

		plaintext := &bytes.Buffer{}
		err = f.OpenWithContext(plaintext, ciphertext, tooLarge)
		require.Error(t, err)
		require.ErrorIs(t, err, canonicalization.ErrPieceTooLarge)
	})
}
