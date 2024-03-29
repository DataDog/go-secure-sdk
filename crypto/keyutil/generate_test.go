// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package keyutil

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	security "github.com/DataDog/go-secure-sdk"

	"golang.org/x/crypto/ssh"
)

var _ io.Reader = (*fakeReader)(nil)

type fakeReader struct{}

func (fr *fakeReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("error")
}

func TestGenerateKeyPair(t *testing.T) {
	t.Parallel()

	t.Run("invalid", func(t *testing.T) {
		t.Parallel()

		pub, pk, err := GenerateKeyPair(0)
		require.Error(t, err)
		require.Nil(t, pub)
		require.Nil(t, pk)
	})

	t.Run("rsa", func(t *testing.T) {
		t.Parallel()

		pub, pk, err := GenerateKeyPair(RSA)
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.IsType(t, &rsa.PublicKey{}, pub)
		require.NotNil(t, pk)
		require.IsType(t, &rsa.PrivateKey{}, pk)
	})

	t.Run("ec", func(t *testing.T) {
		t.Parallel()

		pub, pk, err := GenerateKeyPair(EC)
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.IsType(t, &ecdsa.PublicKey{}, pub)
		require.NotNil(t, pk)
		require.IsType(t, &ecdsa.PrivateKey{}, pk)
	})

	t.Run("ed25519", func(t *testing.T) {
		t.Parallel()

		pub, pk, err := GenerateKeyPair(ED25519)
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.IsType(t, ed25519.PublicKey{}, pub)
		require.NotNil(t, pk)
		require.IsType(t, ed25519.PrivateKey{}, pk)
	})
}

func TestPublicKey(t *testing.T) {
	t.Parallel()

	pk1, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
	require.NoError(t, err)
	pk2, err := ecdsa.GenerateKey(defaultECKeyCurve, rand.Reader)
	require.NoError(t, err)
	pub3, pk3, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pk4, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{Key: pk3}
	jwkPublic := jwk.Public()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()

		pub, err := PublicKey(nil)
		require.Error(t, err)
		require.Nil(t, pub)
	})

	t.Run("typed nil", func(t *testing.T) {
		t.Parallel()

		pub, err := PublicKey((*rsa.PrivateKey)(nil))
		require.Error(t, err)
		require.Nil(t, pub)
	})

	t.Run("rsa", func(t *testing.T) {
		t.Parallel()

		pub, err := PublicKey(pk1)
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.Equal(t, pk1.Public(), pub)

		pub, err = PublicKey(pk1.Public())
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.Equal(t, pk1.Public(), pub)
	})

	t.Run("ec", func(t *testing.T) {
		t.Parallel()

		pub, err := PublicKey(pk2)
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.Equal(t, pk2.Public(), pub)

		pub, err = PublicKey(pk2.Public())
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.Equal(t, pk2.Public(), pub)
	})

	t.Run("ed25519", func(t *testing.T) {
		t.Parallel()

		pub, err := PublicKey(pk3)
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.Equal(t, pub3, pub)

		pub, err = PublicKey(pub3)
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.Equal(t, pub3, pub)
	})

	t.Run("ecdh", func(t *testing.T) {
		t.Parallel()

		pub, err := PublicKey(pk4)
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.True(t, pub.(*ecdh.PublicKey).Equal(pk4.Public()))

		pub, err = PublicKey(pk4.Public())
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.True(t, pub.(*ecdh.PublicKey).Equal(pk4.Public()))
	})

	t.Run("jwk", func(t *testing.T) {
		t.Parallel()

		pub, err := PublicKey(jwk)
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.Equal(t, pub3, pub)

		pub, err = PublicKey(jwkPublic)
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.Equal(t, pub3, pub)

		pub, err = PublicKey(&jwk)
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.Equal(t, pub3, pub)

		pub, err = PublicKey(&jwkPublic)
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.Equal(t, pub3, pub)
	})
}

func TestExtractKey(t *testing.T) {
	t.Parallel()

	pk1, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
	require.NoError(t, err)
	pk2, err := ecdsa.GenerateKey(defaultECKeyCurve, rand.Reader)
	require.NoError(t, err)
	pub3, pk3, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pk4, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubSSH, err := ssh.NewPublicKey(pub3)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{Key: pk3}
	jwkPublic := jwk.Public()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()

		out, err := ExtractKey(nil)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("rsa", func(t *testing.T) {
		t.Parallel()

		out, err := ExtractKey(pk1)
		require.NoError(t, err)
		require.Equal(t, pk1, out)

		out, err = ExtractKey(pk1.Public())
		require.NoError(t, err)
		require.Equal(t, pk1.Public(), out)
	})

	t.Run("ec", func(t *testing.T) {
		t.Parallel()

		out, err := ExtractKey(pk2)
		require.NoError(t, err)
		require.Equal(t, pk2, out)

		out, err = ExtractKey(pk2.Public())
		require.NoError(t, err)
		require.Equal(t, pk2.Public(), out)
	})

	t.Run("ed25519", func(t *testing.T) {
		t.Parallel()

		out, err := ExtractKey(pk3)
		require.NoError(t, err)
		require.Equal(t, pk3, out)

		out, err = ExtractKey(pub3)
		require.NoError(t, err)
		require.Equal(t, pub3, out)
	})

	t.Run("ecdh", func(t *testing.T) {
		t.Parallel()

		out, err := ExtractKey(pk4)
		require.NoError(t, err)
		require.True(t, out.(*ecdh.PrivateKey).Equal(pk4))

		out, err = ExtractKey(pk4.Public())
		require.NoError(t, err)
		require.True(t, out.(*ecdh.PublicKey).Equal(pk4.Public()))
	})

	t.Run("jwk", func(t *testing.T) {
		t.Parallel()

		out, err := ExtractKey(jwk)
		require.NoError(t, err)
		require.Equal(t, pk3, out)

		out, err = ExtractKey(&jwk)
		require.NoError(t, err)
		require.Equal(t, pk3, out)

		out, err = ExtractKey(jwkPublic)
		require.NoError(t, err)
		require.Equal(t, pub3, out)

		out, err = ExtractKey(&jwkPublic)
		require.NoError(t, err)
		require.Equal(t, pub3, out)
	})

	t.Run("bytes", func(t *testing.T) {
		t.Parallel()

		pub, err := ExtractKey([]byte("test"))
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.Equal(t, []byte("test"), pub)
	})

	t.Run("x509 cert", func(t *testing.T) {
		t.Parallel()

		out, err := ExtractKey(&x509.Certificate{
			PublicKey: pub3,
		})
		require.NoError(t, err)
		require.Equal(t, pub3, out)
	})

	t.Run("x509 csr", func(t *testing.T) {
		t.Parallel()

		out, err := ExtractKey(&x509.CertificateRequest{
			PublicKey: pub3,
		})
		require.NoError(t, err)
		require.Equal(t, pub3, out)
	})

	t.Run("ssh public", func(t *testing.T) {
		t.Parallel()

		out, err := ExtractKey(pubSSH)
		require.NoError(t, err)
		require.Equal(t, pub3, out)
	})

	t.Run("ssh cert", func(t *testing.T) {
		t.Parallel()

		out, err := ExtractKey(&ssh.Certificate{
			Key: pubSSH,
		})
		require.NoError(t, err)
		require.Equal(t, pub3, out)
	})
}

func TestVerifyPair(t *testing.T) {
	t.Parallel()

	pk1, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
	require.NoError(t, err)
	pk1bis, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
	require.NoError(t, err)
	pk2, err := ecdsa.GenerateKey(defaultECKeyCurve, rand.Reader)
	require.NoError(t, err)
	pk2bis, err := ecdsa.GenerateKey(defaultECKeyCurve, rand.Reader)
	require.NoError(t, err)
	pub3, pk3, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub3bis, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pk4, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pk4bis, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("nil pub", func(t *testing.T) {
		t.Parallel()

		require.Error(t, VerifyPair(nil, pk1))
	})

	t.Run("nil pk", func(t *testing.T) {
		t.Parallel()

		require.Error(t, VerifyPair(pub3, nil))
	})

	t.Run("rsa", func(t *testing.T) {
		t.Parallel()

		require.Error(t, VerifyPair(pk1.Public(), pk2))
		require.Error(t, VerifyPair(pk1bis.Public(), pk1))
		require.NoError(t, VerifyPair(pk1.Public(), pk1))
	})

	t.Run("ec", func(t *testing.T) {
		t.Parallel()

		require.Error(t, VerifyPair(pk2.Public(), pk3))
		require.Error(t, VerifyPair(pk2bis.Public(), pk2))
		require.NoError(t, VerifyPair(pk2.Public(), pk2))
	})

	t.Run("ed25519", func(t *testing.T) {
		t.Parallel()

		require.Error(t, VerifyPair(pub3, pk1))
		require.Error(t, VerifyPair(pub3bis, pk3))
		require.NoError(t, VerifyPair(pub3, pk3))
	})

	t.Run("ecdh", func(t *testing.T) {
		t.Parallel()

		pub4 := pk4.Public()
		pub4bis := pk4bis.Public()

		require.Error(t, VerifyPair(pub4, pk1))
		require.Error(t, VerifyPair(pub4bis, pk4))
		require.NoError(t, VerifyPair(pub4, pk4))
	})
}

//nolint:paralleltest // Disable parallel testing due to the stateful nature of the FIPS flag
func TestGenerateDefaultKeyPair(t *testing.T) {
	revertFunc := security.SetFIPSMode()
	require.True(t, security.InFIPSMode())
	defer revertFunc()

	pub, priv, err := GenerateDefaultKeyPair()
	require.NoError(t, err)
	require.IsType(t, priv, &ecdsa.PrivateKey{})
	require.IsType(t, pub, &ecdsa.PublicKey{})

	_, _, err = GenerateKeyPair(ED25519)
	require.Error(t, err)

	// Disable FIPS ------------------------------------------------------------
	revertFunc()

	pub, priv, err = GenerateDefaultKeyPair()
	require.NoError(t, err)
	require.IsType(t, priv, ed25519.PrivateKey{})
	require.IsType(t, pub, ed25519.PublicKey{})

	_, _, err = GenerateKeyPair(ED25519)
	require.NoError(t, err)
}

func TestVerifyPublicKey(t *testing.T) {
	t.Parallel()

	pk1, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
	require.NoError(t, err)
	pk2, err := ecdsa.GenerateKey(defaultECKeyCurve, rand.Reader)
	require.NoError(t, err)
	pub3, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pk4, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("nil pub", func(t *testing.T) {
		t.Parallel()

		require.Error(t, VerifyPublicKey(nil, pk1.Public()))
	})

	t.Run("nil pk", func(t *testing.T) {
		t.Parallel()

		require.Error(t, VerifyPublicKey(pub3, nil))
	})

	t.Run("rsa", func(t *testing.T) {
		t.Parallel()

		require.Error(t, VerifyPublicKey(pk1.Public(), pk2.Public()))
		require.NoError(t, VerifyPublicKey(pk1.Public(), pk1.Public()))
	})

	t.Run("ec", func(t *testing.T) {
		t.Parallel()

		require.Error(t, VerifyPublicKey(pk2.Public(), pub3))
		require.NoError(t, VerifyPublicKey(pk2.Public(), pk2.Public()))
	})

	t.Run("ed25519", func(t *testing.T) {
		t.Parallel()

		require.Error(t, VerifyPublicKey(pub3, pk1.Public()))
		require.NoError(t, VerifyPublicKey(pub3, pub3))
	})

	t.Run("ecdh", func(t *testing.T) {
		t.Parallel()

		pub4 := pk4.Public()
		require.Error(t, VerifyPublicKey(pub4, pub3))
		require.NoError(t, VerifyPublicKey(pub4, pub4))
	})
}
