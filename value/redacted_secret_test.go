// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package value

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestAsRedacted(t *testing.T) {
	t.Parallel()

	s := AsRedacted("test")
	require.Equal(t, "test", s.Unwrap())

	t.Run("binary", func(t *testing.T) {
		t.Parallel()

		out, err := s.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, `[redacted]`, string(out))
	})

	t.Run("text", func(t *testing.T) {
		t.Parallel()

		out, err := s.MarshalText()
		require.NoError(t, err)
		require.Equal(t, `[redacted]`, string(out))
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
		require.Equal(t, `"[redacted]"`, string(out))
	})

	t.Run("yaml", func(t *testing.T) {
		t.Parallel()

		out, err := yaml.Marshal(s)
		require.NoError(t, err)
		require.Equal(t, "'[redacted]'\n", string(out))
	})

	t.Run("fmt", func(t *testing.T) {
		t.Parallel()

		out := fmt.Sprintf("%v", s)
		require.Equal(t, "[redacted]", out)
	})

	t.Run("goString", func(t *testing.T) {
		t.Parallel()

		out := s.GoString()
		require.Equal(t, "[redacted]", out)
	})
}
