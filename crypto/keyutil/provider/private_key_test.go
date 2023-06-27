// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrivateKey_Can(t *testing.T) {
	t.Parallel()

	w := &defaultPrivateKey{
		alias:    KeyAlias("testing"),
		key:      nil,
		purposes: Purposes(EncryptionPurpose),
	}

	require.True(t, w.Can(EncryptionPurpose))
	require.False(t, w.Can(SignaturePurpose))
}

func TestPrivateKey_Alias(t *testing.T) {
	t.Parallel()

	w := &defaultPrivateKey{
		alias: KeyAlias("testing"),
	}

	require.Equal(t, KeyAlias("testing"), w.Alias())
}

func TestPrivateKey_Public(t *testing.T) {
	t.Parallel()

	pub, pk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	w := &defaultPrivateKey{
		alias: KeyAlias("testing"),
		key:   pk,
	}

	require.Equal(t, pub, w.Public())
}

func TestPrivateKey_AsBytes(t *testing.T) {
	t.Parallel()

	_, pk, err := ed25519.GenerateKey(strings.NewReader("00000-deterministic-seed-for-testing-purpose-only"))
	require.NoError(t, err)

	t.Run("not exportable", func(t *testing.T) {
		t.Parallel()

		w := &defaultPrivateKey{
			alias:    KeyAlias("testing"),
			key:      pk,
			purposes: Purposes(SignaturePurpose),
		}

		got, err := w.AsBytes()
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("exportable", func(t *testing.T) {
		t.Parallel()

		w := &defaultPrivateKey{
			alias:    KeyAlias("testing"),
			key:      pk,
			purposes: Purposes(SignaturePurpose, ExportableKey),
		}

		got, err := w.AsBytes()
		require.NoError(t, err)
		require.Equal(t, []byte{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2d, 0x64, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2d, 0x73, 0x65, 0x65, 0x64, 0x2d, 0x66, 0x6f, 0x72, 0x2d, 0x74, 0x65, 0x73}, got)
	})
}

func TestPrivateKey_AsPEM(t *testing.T) {
	t.Parallel()

	_, pk, err := ed25519.GenerateKey(strings.NewReader("00000-deterministic-seed-for-testing-purpose-only"))
	require.NoError(t, err)

	t.Run("not exportable", func(t *testing.T) {
		t.Parallel()

		w := &defaultPrivateKey{
			alias:    KeyAlias("testing"),
			key:      pk,
			purposes: Purposes(SignaturePurpose),
		}

		got, err := w.AsPEM()
		require.Error(t, err)
		require.Empty(t, got)
	})

	t.Run("exportable", func(t *testing.T) {
		t.Parallel()

		w := &defaultPrivateKey{
			alias:    KeyAlias("testing"),
			key:      pk,
			purposes: Purposes(SignaturePurpose, ExportableKey),
		}

		got, err := w.AsPEM()
		require.NoError(t, err)
		require.Equal(t, "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDAwMDAwLWRldGVybWluaXN0aWMtc2VlZC1mb3ItdGVz\n-----END PRIVATE KEY-----\n", got)
	})
}

func TestPrivateKey_AsJWK(t *testing.T) {
	t.Parallel()

	_, pk, err := ed25519.GenerateKey(strings.NewReader("00000-deterministic-seed-for-testing-purpose-only"))
	require.NoError(t, err)

	t.Run("not exportable", func(t *testing.T) {
		t.Parallel()

		w := &defaultPrivateKey{
			alias:    KeyAlias("testing"),
			key:      pk,
			purposes: Purposes(SignaturePurpose),
		}

		got, err := w.AsJWK()
		require.Error(t, err)
		require.Empty(t, got)
	})

	t.Run("exportable / sig", func(t *testing.T) {
		t.Parallel()

		w := &defaultPrivateKey{
			alias:    KeyAlias("testing"),
			key:      pk,
			purposes: Purposes(SignaturePurpose, ExportableKey),
		}

		got, err := w.AsJWK()
		require.NoError(t, err)
		require.Equal(t, `{"use":"sig","kty":"OKP","crv":"Ed25519","x":"VYmdjj6A6GE5SPCGCfwhzb0ajYl5fYOKmp6hAUe2RGY","d":"MDAwMDAtZGV0ZXJtaW5pc3RpYy1zZWVkLWZvci10ZXM"}`+"\n", got)
	})

	t.Run("exportable / enc", func(t *testing.T) {
		t.Parallel()

		w := &defaultPrivateKey{
			alias:    KeyAlias("testing"),
			key:      pk,
			purposes: Purposes(EncryptionPurpose, ExportableKey),
		}

		got, err := w.AsJWK()
		require.NoError(t, err)
		require.Equal(t, `{"use":"enc","kty":"OKP","crv":"Ed25519","x":"VYmdjj6A6GE5SPCGCfwhzb0ajYl5fYOKmp6hAUe2RGY","d":"MDAwMDAtZGV0ZXJtaW5pc3RpYy1zZWVkLWZvci10ZXM"}`+"\n", got)
	})
}

func TestPrivateKey_Signer(t *testing.T) {
	t.Parallel()

	_, pk, err := ed25519.GenerateKey(strings.NewReader("00000-deterministic-seed-for-testing-purpose-only"))
	require.NoError(t, err)

	t.Run("no signature flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultPrivateKey{
			alias:    KeyAlias("testing"),
			key:      pk,
			purposes: Purposes(EncryptionPurpose, ExportableKey),
		}

		got, err := w.Signer()
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("conflictual flags", func(t *testing.T) {
		t.Parallel()

		w := &defaultPrivateKey{
			alias:    KeyAlias("testing"),
			key:      pk,
			purposes: Purposes(EncryptionPurpose, SignaturePurpose),
		}

		got, err := w.Signer()
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		w := &defaultPrivateKey{
			alias:    KeyAlias("testing"),
			key:      pk,
			purposes: Purposes(SignaturePurpose),
		}

		got, err := w.Signer()
		require.NoError(t, err)
		require.NotNil(t, got)
	})
}
