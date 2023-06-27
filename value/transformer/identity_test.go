// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package transformer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_identityTransformer_EncodeDecode(t *testing.T) {
	t.Parallel()

	msg := []byte("test")
	transform := Identity()

	t.Run("decode", func(t *testing.T) {
		t.Parallel()

		out, err := transform.Decode(msg)
		require.NoError(t, err)
		require.Equal(t, msg, out)
	})

	t.Run("encode", func(t *testing.T) {
		t.Parallel()

		out, err := transform.Encode(msg)
		require.NoError(t, err)
		require.Equal(t, msg, out)
	})
}
