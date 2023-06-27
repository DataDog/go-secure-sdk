// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"crypto/sha256"
	"testing"

	"github.com/awnumar/memguard"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/crypto/keyutil"
)

func TestSymmetricKey_Can(t *testing.T) {
	t.Parallel()

	w := &defaultSymmetricKey{
		alias:    KeyAlias("testing"),
		key:      nil,
		purposes: Purposes(EncryptionPurpose),
	}

	require.True(t, w.Can(EncryptionPurpose))
	require.False(t, w.Can(SignaturePurpose))
}

func TestSymmetricKey_Alias(t *testing.T) {
	t.Parallel()

	w := &defaultSymmetricKey{
		alias: KeyAlias("testing"),
	}

	require.Equal(t, KeyAlias("testing"), w.Alias())
}

func TestSymmetricKey_AsBytes(t *testing.T) {
	t.Parallel()

	t.Run("not exportable", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("123456789123456789")),
			purposes: Purposes(SignaturePurpose),
		}

		got, err := w.AsBytes()
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("exportable", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("123456789123456789")),
			purposes: Purposes(SignaturePurpose, ExportableKey),
		}

		got, err := w.AsBytes()
		require.NoError(t, err)
		require.Equal(t, []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39}, got)
	})
}

func TestSymmetricKey_ValueEncryption(t *testing.T) {
	t.Parallel()

	t.Run("no encryption flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("123456789123456789")),
			purposes: Purposes(SignaturePurpose),
		}

		got, err := w.ValueEncryption()
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("with encryption flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("123456789123456789")),
			purposes: Purposes(EncryptionPurpose),
		}

		got, err := w.ValueEncryption()
		require.NoError(t, err)
		require.NotNil(t, got)
	})
}

func TestSymmetricKey_ConvergentEncryption(t *testing.T) {
	t.Parallel()

	t.Run("no encryption flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("12345678912345678912345678912345")),
			purposes: Purposes(SignaturePurpose),
		}

		got, err := w.ConvergentEncryption()
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("with encryption flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("12345678912345678912345678912345")),
			purposes: Purposes(EncryptionPurpose),
		}

		got, err := w.ConvergentEncryption()
		require.NoError(t, err)
		require.NotNil(t, got)
	})
}

func TestSymmetricKey_ChunkedEncryption(t *testing.T) {
	t.Parallel()

	t.Run("no encryption flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("123456789123456789")),
			purposes: Purposes(SignaturePurpose),
		}

		got, err := w.ChunkedEncryption()
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("with encryption flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("123456789123456789")),
			purposes: Purposes(EncryptionPurpose),
		}

		got, err := w.ChunkedEncryption()
		require.NoError(t, err)
		require.NotNil(t, got)
	})
}

func TestSymmetricKey_HMAC(t *testing.T) {
	t.Parallel()

	t.Run("no signature flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("123456789123456789")),
			purposes: Purposes(EncryptionPurpose),
		}

		got, err := w.HMAC(sha256.New)
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("with signature flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("123456789123456789")),
			purposes: Purposes(SignaturePurpose),
		}

		got, err := w.HMAC(sha256.New)
		require.NoError(t, err)
		require.NotNil(t, got)
	})
}

func TestSymmetricKey_NewCipher(t *testing.T) {
	t.Parallel()

	t.Run("no encryption flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("1234567891234567")),
			purposes: Purposes(SignaturePurpose),
		}

		got, err := w.NewCipher()
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("with signature flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("1234567891234567")),
			purposes: Purposes(EncryptionPurpose),
		}

		got, err := w.NewCipher()
		require.NoError(t, err)
		require.NotNil(t, got)
	})
}

func TestSymmetricKey_DeriveSymmetric(t *testing.T) {
	t.Parallel()

	t.Run("no derivation flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("123456789123456789")),
			purposes: Purposes(SignaturePurpose),
		}

		got, err := w.DeriveSymmetric(nil, []byte("configuration-encryption"), 32, EncryptionPurpose)
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("with derivation flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("123456789123456789")),
			purposes: Purposes(KeyDerivationPurpose),
		}

		got, err := w.DeriveSymmetric(nil, []byte("configuration-encryption"), 32, EncryptionPurpose, ExportableKey)
		require.NoError(t, err)
		require.NotNil(t, got)

		raw, err := got.AsBytes()
		require.NoError(t, err)
		require.Equal(t, []byte{0x8e, 0x38, 0x3e, 0xd, 0x1c, 0xbe, 0xb1, 0x2e, 0xb2, 0x5b, 0xbf, 0x28, 0xba, 0xc, 0xe9, 0xc0, 0xe9, 0xac, 0xaf, 0x66, 0xa8, 0xbc, 0x68, 0x8d, 0x73, 0xb7, 0x72, 0xdd, 0x17, 0x85, 0x43, 0x8c}, raw)

		require.Contains(t, got.Alias(), "urn:datadog:kms:v1:")
	})

	t.Run("with different salt", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("123456789123456789")),
			purposes: Purposes(KeyDerivationPurpose),
		}

		got, err := w.DeriveSymmetric([]byte("00001"), []byte("configuration-encryption"), 32, EncryptionPurpose, ExportableKey)
		require.NoError(t, err)
		require.NotNil(t, got)

		raw, err := got.AsBytes()
		require.NoError(t, err)
		require.Equal(t, []byte{0xaa, 0xe8, 0x72, 0xe3, 0x8a, 0xea, 0x1e, 0x3f, 0xbc, 0x4b, 0x82, 0x76, 0xde, 0x3a, 0xbd, 0x30, 0x7b, 0x93, 0xb7, 0x34, 0xab, 0x8f, 0xb8, 0xa5, 0xb4, 0x52, 0xdf, 0xe8, 0xd0, 0xc5, 0x63, 0x93}, raw)

		require.Contains(t, got.Alias(), "urn:datadog:kms:v1:")
	})
}

func TestSymmetricKey_DeriveAsymmetric(t *testing.T) {
	t.Parallel()

	t.Run("no derivation flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("123456789123456789")),
			purposes: Purposes(SignaturePurpose),
		}

		pub, pk, err := w.DeriveAsymmetric(nil, []byte("configuration-signature"), keyutil.ED25519, SignaturePurpose)
		require.Error(t, err)
		require.Nil(t, pub)
		require.Nil(t, pk)
	})

	t.Run("with derivation flag", func(t *testing.T) {
		t.Parallel()

		w := &defaultSymmetricKey{
			alias:    KeyAlias("testing"),
			key:      memguard.NewEnclave([]byte("123456789123456789")),
			purposes: Purposes(KeyDerivationPurpose),
		}

		pub, pk, err := w.DeriveAsymmetric(nil, []byte("configuration-signature"), keyutil.ED25519, SignaturePurpose)
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.NotNil(t, pk)
		require.Equal(t, pub.Alias(), pk.Alias())
	})
}
