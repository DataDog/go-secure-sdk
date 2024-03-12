// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package keyutil

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

var serverCertPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIEZjCCA06gAwIBAgIUJmJQ3xVko+fzT2wM68QwqinLvWkwDQYJKoZIhvcNAQEL
BQAwgY8xCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhOZXcgWW9yazERMA8GA1UEBxMI
TmV3IFlvcmsxFTATBgNVBAoTDERhdGFkb2csIEluYzEcMBoGA1UECxMTU2VydmVy
IFRlc3QgUm9vdCBDQTElMCMGA1UEAxMcRGF0YWRvZyBUZXN0IEludGVybWVkaWF0
ZSBDQTAeFw0yMzAxMDYxMzU1MDBaFw0yNDAxMDYxMzU1MDBaMIGRMQswCQYDVQQG
EwJVUzERMA8GA1UECBMITmV3IFlvcmsxETAPBgNVBAcTCE5ldyBZb3JrMRUwEwYD
VQQKEwxEYXRhZG9nLCBJbmMxITAfBgNVBAsTGEZha2UgU2VydmVyIFRlc3QgUm9v
dCBDQTEiMCAGA1UEAwwZ44GT44KT44Gr44Gh44Gv5LiW55WMLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBANxjwMlRE1Z13ao5whZWF/ZskNHngIt1
ipjlS3mQsn65T4yexnOuxKq2UFejgrE3L7tn/yzfqBBQGPOzmPJrGfuFyLLggttD
L3ly5fBbKnu4eTRo1N0yionFrsO1nJVekihOjhjJBAGGm/g4R6T+TaXWZX8rDm4J
jcfD39m+z0GpSeHD7iST9k/TTou7qPDe7a/H/3kCX5v0yNlfhe+99Xmso9vQUjsh
adT8/GI0aqAzE3YAP/kfj8PES+W4k5OkA8g5Oc7VMx77R4IOhXEzPuCfgmiVsxzq
RYpUnpsn252sCs34vL7UH1k3zdukzcUwWzt4yrzPC2zNRErSrWruXvMCAwEAAaOB
tTCBsjAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0T
AQH/BAIwADAdBgNVHQ4EFgQUTT6OQhtYEoJzLBFEqitRIYxLWZIwHwYDVR0jBBgw
FoAUtEEnb/IBcqkrK5X1tJIUqbq2li4wPQYDVR0RBDYwNIIJbG9jYWxob3N0ggVb
OjoxXYIaeG4tLTI4ajJhM2FyMXBwNzVvdm03Yy5jb22HBH8AAAEwDQYJKoZIhvcN
AQELBQADggEBAB6mkLyxIQowLnaox0RCwTl6fe55QfBM0WuYVOFKjxsCnHwldFyq
bAw+Pr06R40GuZsmJi3+KJcVe8Z2wWrHcKHi/eua0N06Xl6LD8zkFJndHaLMqOEv
/nO7+wn4EhcGrrXZ+IEdKnpz4alpvT8PEi7hd6qdlb81/oKTZYIPxdntMHqWgSnZ
xSAy+IgkF06SpkmFctg1vKPRNkb5Q9yBZq4+IBkekYTwrATxZmMxLhO8IOhHXM0V
m/U6CWcUxZzcI6qB77J1zDnUSSRFSS2H52rVsWMIsonxIbnl3wioeiJcfDp9eaEe
VsJ2BMO0RQVW7SHeLzY8ff1w+ihbt/v/M3c=
-----END CERTIFICATE-----`)

func TestPublicKeyFingerprint(t *testing.T) {
	t.Parallel()

	b, _ := pem.Decode(serverCertPEM)
	require.NotNil(t, b)
	cert, err := x509.ParseCertificate(b.Bytes)
	require.NoError(t, err)
	require.NotNil(t, cert)

	t.Run("nil", func(t *testing.T) {
		t.Parallel()

		fgr, err := PublicKeyFingerprint(nil)
		require.Error(t, err)
		require.Empty(t, fgr)
	})

	t.Run("rsa", func(t *testing.T) {
		t.Parallel()

		block, _ := pem.Decode([]byte(pkcs8RsaKeyPEM))
		pkRaw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)
		require.IsType(t, &rsa.PrivateKey{}, pkRaw)
		pk, _ := pkRaw.(*rsa.PrivateKey)

		fgr, err := PublicKeyFingerprint(pk)
		require.NoError(t, err)
		require.Equal(t, []byte{0x7b, 0x9, 0xc2, 0x2d, 0xc, 0xaa, 0x7a, 0xa8, 0xf6, 0x33, 0xf7, 0xe2, 0x80, 0x4, 0x55, 0xa7, 0xe1, 0x75, 0x3e, 0x4f, 0x5e, 0xbc, 0x79, 0xde, 0x5f, 0x76, 0x4e, 0xa1, 0xdb, 0x19, 0xfd, 0x3e}, fgr)

		fgr2, err := PublicKeyFingerprint(pk.Public())
		require.NoError(t, err)
		require.Equal(t, fgr, fgr2)
	})

	t.Run("ec", func(t *testing.T) {
		t.Parallel()

		block, _ := pem.Decode([]byte(pkcs8EcKeyPEM))
		pkRaw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)
		require.IsType(t, &ecdsa.PrivateKey{}, pkRaw)
		pk, _ := pkRaw.(*ecdsa.PrivateKey)

		fgr, err := PublicKeyFingerprint(pk)
		require.NoError(t, err)
		require.Equal(t, []byte{0xc, 0x92, 0x64, 0xed, 0x52, 0x31, 0x26, 0xe4, 0xd6, 0xcf, 0xff, 0x22, 0xd1, 0xe3, 0xd7, 0x9b, 0xf1, 0xe3, 0x82, 0x3, 0xae, 0xca, 0x85, 0xf0, 0xc3, 0xc8, 0x2c, 0xaa, 0xb0, 0xcf, 0xc2, 0xba}, fgr)

		fgr2, err := PublicKeyFingerprint(pk.Public())
		require.NoError(t, err)
		require.Equal(t, fgr, fgr2)
	})

	t.Run("ed25519", func(t *testing.T) {
		t.Parallel()

		block, _ := pem.Decode([]byte(pkcs8Ed25519KeyPEM))
		pkRaw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)
		require.IsType(t, ed25519.PrivateKey{}, pkRaw)
		pk, _ := pkRaw.(ed25519.PrivateKey)

		fgr, err := PublicKeyFingerprint(pk)
		require.NoError(t, err)
		require.Equal(t, []byte{0xf6, 0x25, 0x67, 0xe7, 0x64, 0xca, 0xc2, 0xb6, 0xc7, 0xbe, 0x9b, 0x59, 0xb5, 0x7b, 0x88, 0x74, 0xea, 0x32, 0x41, 0xcb, 0x4b, 0x4f, 0x5f, 0xb5, 0xa, 0x46, 0x49, 0x50, 0x8a, 0xb9, 0xd3, 0x1d}, fgr)

		fgr2, err := PublicKeyFingerprint(pk.Public())
		require.NoError(t, err)
		require.Equal(t, fgr, fgr2)
	})

	t.Run("curve25519", func(t *testing.T) {
		t.Parallel()

		block, _ := pem.Decode([]byte(pkcs8Curve25519KeyPEM))
		pkRaw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)
		require.IsType(t, &ecdh.PrivateKey{}, pkRaw)
		pk, _ := pkRaw.(*ecdh.PrivateKey)

		fgr, err := PublicKeyFingerprint(pk)
		require.NoError(t, err)
		require.Equal(t, []byte{0x78, 0x14, 0x55, 0xfe, 0x79, 0x21, 0xaf, 0xba, 0x8d, 0x7d, 0xab, 0x4b, 0x7e, 0x22, 0xc6, 0x2, 0x2d, 0x3d, 0x13, 0x2b, 0x85, 0x59, 0x7c, 0xc, 0x81, 0x65, 0x33, 0x26, 0x63, 0xe9, 0xb, 0xaa}, fgr)

		fgr2, err := PublicKeyFingerprint(pk.Public())
		require.NoError(t, err)
		require.Equal(t, fgr, fgr2)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		fgr, err := PublicKeyFingerprint(cert)
		require.NoError(t, err)
		require.Equal(t, []byte{0x93, 0x51, 0xdd, 0xa8, 0x7a, 0x49, 0xdb, 0x21, 0x2, 0xae, 0xf9, 0x7d, 0xec, 0x41, 0xa5, 0x8b, 0xd6, 0xdf, 0x92, 0x45, 0x61, 0xc, 0x87, 0x74, 0x4b, 0x39, 0xa0, 0xef, 0x3d, 0x95, 0xa0, 0x60}, fgr)
	})
}
