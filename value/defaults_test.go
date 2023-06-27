// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package value

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/DataDog/go-secure-sdk/crypto/encryption"
)

func TestAsEncrypted(t *testing.T) {
	t.Parallel()

	// Assign specific global encryption key
	key := []byte("000-deterministic-encryption-key")
	require.NoError(t, SetDefaultEncryptionKey(key))

	msg := "test"
	s := AsEncrypted(msg)
	require.Equal(t, "test", s.Unwrap())

	t.Run("binary", func(t *testing.T) {
		t.Parallel()

		out, err := s.MarshalBinary()
		require.NoError(t, err)

		plaintext, err := encryption.Open([][]byte{[]byte("000-deterministic-encryption-key")}, out)
		require.NoError(t, err)
		require.Equal(t, []byte(`"test"`), plaintext)
	})

	t.Run("text", func(t *testing.T) {
		t.Parallel()

		out, err := s.MarshalText()
		require.NoError(t, err)

		decoded, err := base64.RawURLEncoding.DecodeString(string(out))
		require.NoError(t, err)

		plaintext, err := encryption.Open([][]byte{[]byte("000-deterministic-encryption-key")}, decoded)
		require.NoError(t, err)
		require.Equal(t, []byte(`"test"`), plaintext)
	})

	t.Run("string", func(t *testing.T) {
		t.Parallel()

		out := s.String()
		require.Equal(t, `[redacted]`, out)
	})

	t.Run("json", func(t *testing.T) {
		t.Parallel()

		out, err := json.Marshal(s)
		require.NoError(t, err)

		var raw string
		require.NoError(t, json.Unmarshal(out, &raw))

		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		require.NoError(t, err)

		plaintext, err := encryption.Open([][]byte{[]byte("000-deterministic-encryption-key")}, decoded)
		require.NoError(t, err)
		require.Equal(t, []byte(`"test"`), plaintext)
	})

	t.Run("yaml", func(t *testing.T) {
		t.Parallel()

		out, err := yaml.Marshal(s)
		require.NoError(t, err)

		var raw string
		require.NoError(t, yaml.Unmarshal(out, &raw))

		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		require.NoError(t, err)

		plaintext, err := encryption.Open([][]byte{[]byte("000-deterministic-encryption-key")}, decoded)
		require.NoError(t, err)
		require.Equal(t, []byte(`"test"`), plaintext)
	})

	t.Run("fmt", func(t *testing.T) {
		t.Parallel()

		out := fmt.Sprintf("%v", s)

		decoded, err := base64.RawURLEncoding.DecodeString(out)
		require.NoError(t, err)

		plaintext, err := encryption.Open([][]byte{[]byte("000-deterministic-encryption-key")}, decoded)
		require.NoError(t, err)
		require.Equal(t, []byte(`"test"`), plaintext)
	})

	t.Run("goString", func(t *testing.T) {
		t.Parallel()

		out := s.GoString()
		require.Equal(t, "[redacted]", out)
	})
}
