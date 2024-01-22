package certutil

import (
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

func TestCertificateFingerprint(t *testing.T) {
	t.Parallel()

	b, _ := pem.Decode(serverCertPEM)
	require.NotNil(t, b)
	cert, err := x509.ParseCertificate(b.Bytes)
	require.NoError(t, err)
	require.NotNil(t, cert)

	t.Run("nil certificate", func(t *testing.T) {
		t.Parallel()

		fgr, err := Fingerprint(nil)
		require.Error(t, err)
		require.Empty(t, fgr)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		fgr, err := Fingerprint(cert)
		require.NoError(t, err)
		require.Equal(t, []byte{0x13, 0xf0, 0x13, 0xba, 0x27, 0x52, 0x27, 0x62, 0xe7, 0x6a, 0x74, 0x21, 0xa2, 0x8, 0x9c, 0x40, 0x7a, 0x47, 0x6c, 0xef, 0x87, 0x50, 0xf8, 0xa2, 0x31, 0xfa, 0x73, 0x6e, 0x9b, 0xb4, 0xbf, 0x55}, fgr)
	})
}
