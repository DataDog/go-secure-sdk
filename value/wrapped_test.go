// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package value

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/crypto/encryption"
	"github.com/DataDog/go-secure-sdk/value/transformer"
)

func TestAsWrapped(t *testing.T) {
	t.Parallel()

	aead, err := encryption.Value([]byte("000-deterministic-encryption-key"))
	require.NoError(t, err)

	s := AsWrapped("test", transformer.Encryption(aead))
	require.Equal(t, "test", s.Unwrap())

	t.Run("binary", func(t *testing.T) {
		t.Parallel()

		out, err := s.MarshalBinary()
		require.NoError(t, err)

		secret := AsWrapped("", transformer.Encryption(aead))
		require.NoError(t, secret.UnmarshalBinary(out))
		require.Equal(t, `test`, secret.Unwrap())
	})

	t.Run("text", func(t *testing.T) {
		t.Parallel()

		out, err := s.MarshalText()
		require.NoError(t, err)

		secret := AsWrapped("", transformer.Encryption(aead))
		require.NoError(t, secret.UnmarshalText(out))
		require.Equal(t, `test`, secret.Unwrap())
	})

	t.Run("string", func(t *testing.T) {
		t.Parallel()

		out := s.String()
		require.Equal(t, `[redacted]`, out)
	})

	t.Run("json", func(t *testing.T) {
		t.Parallel()

		out, err := json.Marshal(&s)
		require.NoError(t, err)
		require.NotEmpty(t, out)

		secret := AsWrapped("", transformer.Encryption(aead))
		require.NoError(t, json.Unmarshal(out, &secret))
		require.Equal(t, `test`, secret.Unwrap())
	})

	t.Run("sql", func(t *testing.T) {
		t.Parallel()

		out, err := s.Value()
		require.NoError(t, err)
		require.NotEmpty(t, out)

		secret := AsWrapped("", transformer.Encryption(aead))
		require.NoError(t, secret.Scan(out))
		require.Equal(t, `test`, secret.Unwrap())
	})
}
