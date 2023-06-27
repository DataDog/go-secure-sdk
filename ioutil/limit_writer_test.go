// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package ioutil

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

func TestLimitWriter(t *testing.T) {
	t.Run("nominal case", func(t *testing.T) {
		t.Parallel()

		out := &bytes.Buffer{}
		tw := LimitWriter(out, 2048)
		written, err := io.CopyN(tw, randomness.Reader, 1024)
		require.NoError(t, err)
		require.Equal(t, int64(1024), written)
		require.Equal(t, int(1024), out.Len())
	})

	t.Run("nil writer", func(t *testing.T) {
		t.Parallel()

		tw := LimitWriter(nil, 1024)
		written, err := io.CopyN(tw, randomness.Reader, 2048)
		require.Error(t, err)
		require.Equal(t, int64(0), written)
	})

	t.Run("limited", func(t *testing.T) {
		t.Parallel()

		out := &bytes.Buffer{}
		tw := LimitWriter(out, 1024)
		written, err := io.CopyN(tw, randomness.Reader, 2048)
		require.NoError(t, err)
		require.Equal(t, int64(2048), written)
		require.Equal(t, int(1024), out.Len())
	})
}
