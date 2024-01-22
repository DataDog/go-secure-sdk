package provider

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/crypto/keyutil"
)

func TestPublicKey_Can(t *testing.T) {
	t.Parallel()

	w := &defaultPublicKey{
		alias:    KeyAlias("testing"),
		key:      nil,
		purposes: Purposes(EncryptionPurpose),
	}

	require.True(t, w.Can(EncryptionPurpose))
	require.False(t, w.Can(SignaturePurpose))
}

func TestPublicKey_Alias(t *testing.T) {
	t.Parallel()

	w := &defaultPublicKey{
		alias: KeyAlias("testing"),
	}

	require.Equal(t, KeyAlias("testing"), w.Alias())
}

func TestPublicKey_Public(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	w := &defaultPublicKey{
		alias: KeyAlias("testing"),
		key:   pub,
	}

	require.Equal(t, pub, w.Public())
}

func TestPublicKey_AsBytes(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(strings.NewReader("00000-deterministic-seed-for-testing-purpose-only"))
	require.NoError(t, err)

	w := &defaultPublicKey{
		alias:    KeyAlias("testing"),
		key:      pub,
		purposes: Purposes(SignaturePurpose, ExportableKey),
	}

	got, err := w.AsBytes()
	require.NoError(t, err)
	require.Equal(t, []byte{0x30, 0x2a, 0x30, 0x5, 0x6, 0x3, 0x2b, 0x65, 0x70, 0x3, 0x21, 0x0, 0x55, 0x89, 0x9d, 0x8e, 0x3e, 0x80, 0xe8, 0x61, 0x39, 0x48, 0xf0, 0x86, 0x9, 0xfc, 0x21, 0xcd, 0xbd, 0x1a, 0x8d, 0x89, 0x79, 0x7d, 0x83, 0x8a, 0x9a, 0x9e, 0xa1, 0x1, 0x47, 0xb6, 0x44, 0x66}, got)
}

func TestPublicKey_AsPEM(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(strings.NewReader("00000-deterministic-seed-for-testing-purpose-only"))
	require.NoError(t, err)

	w := &defaultPublicKey{
		alias:    KeyAlias("testing"),
		key:      pub,
		purposes: Purposes(SignaturePurpose, ExportableKey),
	}

	got, err := w.AsPEM()
	require.NoError(t, err)
	require.Equal(t, "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAVYmdjj6A6GE5SPCGCfwhzb0ajYl5fYOKmp6hAUe2RGY=\n-----END PUBLIC KEY-----\n", got)
}

func TestPublicKey_AsJWK(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(strings.NewReader("00000-deterministic-seed-for-testing-purpose-only"))
	require.NoError(t, err)

	t.Run("sig", func(t *testing.T) {
		t.Parallel()

		w := &defaultPublicKey{
			alias:    KeyAlias("testing"),
			key:      pub,
			purposes: Purposes(SignaturePurpose),
		}

		got, err := w.AsJWK()
		require.NoError(t, err)
		require.Equal(t, `{"use":"sig","kty":"OKP","crv":"Ed25519","x":"VYmdjj6A6GE5SPCGCfwhzb0ajYl5fYOKmp6hAUe2RGY"}`+"\n", got)
	})

	t.Run("enc", func(t *testing.T) {
		t.Parallel()

		w := &defaultPublicKey{
			alias:    KeyAlias("testing"),
			key:      pub,
			purposes: Purposes(EncryptionPurpose),
		}

		got, err := w.AsJWK()
		require.NoError(t, err)
		require.Equal(t, `{"use":"enc","kty":"OKP","crv":"Ed25519","x":"VYmdjj6A6GE5SPCGCfwhzb0ajYl5fYOKmp6hAUe2RGY"}`+"\n", got)
	})
}

func TestPublicKey_AsCabin(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(strings.NewReader("00000-deterministic-seed-for-testing-purpose-only"))
	require.NoError(t, err)

	t.Run("exportable", func(t *testing.T) {
		t.Parallel()

		w := &defaultPublicKey{
			alias:    KeyAlias("testing"),
			key:      pub,
			purposes: Purposes(SignaturePurpose, ExportableKey),
		}

		got, err := w.AsCabin([]byte("test-password-000"))
		require.NoError(t, err)

		k, err := keyutil.FromCabinPEM(bytes.NewReader(got), []byte("test-password-000"))
		require.NoError(t, err)
		require.Equal(t, pub, k)
	})
}

func TestPublicKey_Verifier(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(strings.NewReader("00000-deterministic-seed-for-testing-purpose-only"))
	require.NoError(t, err)

	t.Run("no signature flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultPublicKey{
			alias:    KeyAlias("testing"),
			key:      pub,
			purposes: Purposes(EncryptionPurpose, ExportableKey),
		}

		got, err := w.Verifier()
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("conflictual flags", func(t *testing.T) {
		t.Parallel()

		w := &defaultPublicKey{
			alias:    KeyAlias("testing"),
			key:      pub,
			purposes: Purposes(EncryptionPurpose, SignaturePurpose),
		}

		got, err := w.Verifier()
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		w := &defaultPublicKey{
			alias:    KeyAlias("testing"),
			key:      pub,
			purposes: Purposes(SignaturePurpose),
		}

		got, err := w.Verifier()
		require.NoError(t, err)
		require.NotNil(t, got)
	})
}
