package tlsclient

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DataDog/go-secure-sdk/crypto/keyutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateAndSignCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()

	// Generate the key
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Prepare certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Datadoc, Inc"},
			CommonName:   "localhost",
		},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	// Create self-signed certificate.
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, certPrivKey.Public(), certPrivKey)
	require.NoError(t, err)

	// pack as certificate
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// pack private key
	certPrivKeyRaw, err := x509.MarshalPKCS8PrivateKey(certPrivKey)
	require.NoError(t, err)

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: certPrivKeyRaw,
	})

	return certPEM.Bytes(), certPrivKeyPEM.Bytes()
}

//nolint:paralleltest // Disable parallel testing due HTTP server statefulness.
func TestPinnedDialer(t *testing.T) {
	t.Parallel()

	// Generate self-signed server certificate.
	serverCertPEM, serverKeyPEM := generateAndSignCertificate(t)

	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	// Initialize a TLS HTTP Server.
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(serverCertPEM))

	// Assign server TLS configuration.
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		RootCAs:      pool,
	}

	// Start the TLS Server.
	ts.StartTLS()
	t.Cleanup(func() {
		ts.Close()
	})

	t.Run("match found", func(t *testing.T) {
		// Compute expected fingerprint
		expectedFingerprint, err := keyutil.PublicKeyFingerprint(serverCert.PrivateKey)
		require.NoError(t, err)

		client := ts.Client()
		client.Transport = &http.Transport{
			DialTLSContext: PinnedDialer(&tls.Config{
				InsecureSkipVerify: true,
			}, expectedFingerprint),
		}

		// Do a dummy request to invoke the dialer.
		req, err := http.NewRequest(http.MethodPost, ts.URL, nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() {
			resp.Body.Close()
		})

		assert.Exactly(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("no match", func(t *testing.T) {
		client := ts.Client()
		client.Transport = &http.Transport{
			DialTLSContext: PinnedDialer(&tls.Config{
				InsecureSkipVerify: true,
			}, nil),
		}

		// Do a dummy request to invoke the dialer.
		req, err := http.NewRequest(http.MethodPost, ts.URL, nil)
		require.NoError(t, err)
		_, err = client.Do(req)
		require.Error(t, err)
	})
}
