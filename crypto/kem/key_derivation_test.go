package kem

import (
	"crypto/ecdh"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestXDeriver(t *testing.T) {
	scheme := DHX25519HKDFSHA256()

	ikmE, _ := hex.DecodeString("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234")
	skEm, _ := hex.DecodeString("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
	pkEm, _ := hex.DecodeString("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")

	pk, sk, err := xDeriver(scheme.(*dhkem), ikmE)
	require.NoError(t, err)
	require.Equal(t, pk.Bytes(), pkEm)
	require.Equal(t, sk.Bytes(), skEm)
}

func TestECDeriver(t *testing.T) {
	t.Run("P-256", func(t *testing.T) {
		scheme := DHP256HKDFSHA256()

		ikmE, _ := hex.DecodeString("798d82a8d9ea19dbc7f2c6dfa54e8a6706f7cdc119db0813dacf8440ab37c857")
		skEm, _ := hex.DecodeString("6b8de0873aed0c1b2d09b8c7ed54cbf24fdf1dfc7a47fa501f918810642d7b91")
		pkEm, _ := hex.DecodeString("042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e15b79e264a98f2c535ef06745f3d308624414153b22c7332bc1e691cb4af4d53454")

		pk, sk, err := ecDeriver(ecdh.P256())(scheme.(*dhkem), ikmE)
		require.NoError(t, err)
		require.Equal(t, pk.Bytes(), pkEm)
		require.Equal(t, sk.Bytes(), skEm)
	})

	// P-384 not present in vector tests.

	t.Run("P-521", func(t *testing.T) {
		scheme := DHP521HKDFSHA512()

		ikmE, _ := hex.DecodeString("2270197b9f64f86e0eecd49076d05f8fb9f5272c0e7ea519182ae76417b69e7a16f4b0e44116023857b509b84c8a7e48686940cb3ff7e1266ab7c0f3a7ff7770f21b")
		skEm, _ := hex.DecodeString("01e1b006811a044a56ce62427cd2ea34b19ef6990c510f6e08ed5e1056c2ac39f61687134d292ae559fd070e31428ab2873b798908c3579e7a6f57e2e26d0dc532e7")
		pkEm, _ := hex.DecodeString("0401a514f452f316bda875c37ca40dd2ee5d93be7c80a81c423fb1500974d87314ffbe8d5aefd34e69d44f310cdf752519cad0a2ef1a240d67049e57222291aaffbb85004680e6232e8555c97eba731c7e0a47a1063e039d4c9e915da35f53ce5310ebdc0a9586b222ebad01ed9bbfb844c3fab4e49c06de034ef780bfc74b774cfabe93ac")

		pk, sk, err := ecDeriver(ecdh.P521())(scheme.(*dhkem), ikmE)
		require.NoError(t, err)
		require.Equal(t, pk.Bytes(), pkEm)
		require.Equal(t, sk.Bytes(), skEm)
	})
}
