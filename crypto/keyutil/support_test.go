// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package keyutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"

	security "github.com/DataDog/go-secure-sdk"
)

func TestIsUsable(t *testing.T) {
	t.Parallel()

	pk1, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
	require.NoError(t, err)
	pk2, err := ecdsa.GenerateKey(defaultECKeyCurve, rand.Reader)
	require.NoError(t, err)
	pub3, pk3, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("nil", func(t *testing.T) {
		t.Parallel()

		err := IsUsable(nil)
		require.Error(t, err)
	})

	t.Run("rsa", func(t *testing.T) {
		t.Parallel()

		err := IsUsable(pk1)
		require.NoError(t, err)

		err = IsUsable(pk1.Public())
		require.NoError(t, err)
	})

	t.Run("ec", func(t *testing.T) {
		t.Parallel()

		err := IsUsable(pk2)
		require.NoError(t, err)

		err = IsUsable(pk2.Public())
		require.NoError(t, err)
	})

	t.Run("ed25519", func(t *testing.T) {
		t.Parallel()

		err := IsUsable(pk3)
		require.NoError(t, err)

		err = IsUsable(pub3)
		require.NoError(t, err)
	})

	t.Run("unknown", func(t *testing.T) {
		t.Parallel()

		err := IsUsable(&struct{}{})
		require.Error(t, err)
	})
}

//nolint:paralleltest // Disable parallel testing due to the stateful nature of the FIPS flag
func TestIsUsableFIPS(t *testing.T) {
	revertFunc := security.SetFIPSMode()
	require.True(t, security.InFIPSMode())
	defer revertFunc()

	pk1, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
	require.NoError(t, err)
	pk2, err := ecdsa.GenerateKey(defaultECKeyCurve, rand.Reader)
	require.NoError(t, err)
	pub3, pk3, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("nil", func(t *testing.T) {
		err := IsUsable(nil)
		require.Error(t, err)
	})

	t.Run("rsa", func(t *testing.T) {
		err := IsUsable(pk1)
		require.NoError(t, err)

		err = IsUsable(pk1.Public())
		require.NoError(t, err)
	})

	t.Run("ec", func(t *testing.T) {
		err := IsUsable(pk2)
		require.NoError(t, err)

		err = IsUsable(pk2.Public())
		require.NoError(t, err)
	})

	t.Run("ed25519", func(t *testing.T) {
		err := IsUsable(pk3)
		require.Error(t, err)

		err = IsUsable(pub3)
		require.Error(t, err)
	})
}
