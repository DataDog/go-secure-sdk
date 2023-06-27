// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package transformer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/crypto/encryption"
)

func Test_encryptionTransformer_EncodeDecode(t *testing.T) {
	aead, err := encryption.Value([]byte("000-deterministic-encryption-key"))
	require.NoError(t, err)

	transform := Encryption(aead)

	t.Run("empty ciphertext", func(t *testing.T) {
		t.Parallel()

		ciphertext := []byte("")
		out, err := transform.Decode(ciphertext)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("empty plaintext", func(t *testing.T) {
		t.Parallel()

		plaintext := []byte("")

		ciphertext, err := transform.Encode(plaintext)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)

		out, err := transform.Decode(ciphertext)
		require.NoError(t, err)
		require.Equal(t, plaintext, out)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		plaintext := []byte("test")

		ciphertext, err := transform.Encode(plaintext)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)

		out, err := transform.Decode(ciphertext)
		require.NoError(t, err)
		require.Equal(t, plaintext, out)
	})
}
