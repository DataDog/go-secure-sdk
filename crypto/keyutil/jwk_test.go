// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package keyutil

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

func TestToJWK(t *testing.T) {
	t.Parallel()

	t.Run("nil key", func(t *testing.T) {
		t.Parallel()

		_, err := ToJWK(nil)
		require.Error(t, err)
	})

	t.Run("ED25519", func(t *testing.T) {
		t.Parallel()

		pub, pk, err := GenerateKeyPairWithRand(strings.NewReader("Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk"), ED25519)
		require.NoError(t, err)

		pubJWK, err := ToJWK(pub)
		require.NoError(t, err)
		pubRaw, err := json.Marshal(pubJWK)
		require.NoError(t, err)
		require.Equal(t, `{"kty":"OKP","kid":"g1nc0NnN4CMEbdsNL-7X7TFxVtGZsBSTOgp2wuUFx8s","crv":"Ed25519","x":"1W8l-m7roH-0ma4gWUwbbwotRLcPrLkW39zJd5rarnE"}`, string(pubRaw))

		pkJWK, err := ToJWK(pk)
		require.NoError(t, err)
		pkRaw, err := json.Marshal(pkJWK)
		require.NoError(t, err)
		require.Equal(t, `{"kty":"OKP","kid":"g1nc0NnN4CMEbdsNL-7X7TFxVtGZsBSTOgp2wuUFx8s","crv":"Ed25519","x":"1W8l-m7roH-0ma4gWUwbbwotRLcPrLkW39zJd5rarnE","d":"VXYzOEJ5R0NaVThXUDE4UG1tSWRjcFZteDAwUUEzeE4"}`, string(pkRaw))
	})
}

func TestToPublicJWKS(t *testing.T) {
	t.Parallel()

	t.Run("nil key", func(t *testing.T) {
		t.Parallel()

		_, err := ToPublicJWKS(nil)
		require.Error(t, err)
	})

	t.Run("ED25519", func(t *testing.T) {
		t.Parallel()

		pub, pk, err := GenerateKeyPairWithRand(strings.NewReader("Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk"), ED25519)
		require.NoError(t, err)

		pubJWK, err := ToPublicJWKS(pub)
		require.NoError(t, err)
		pubRaw, err := json.Marshal(pubJWK)
		require.NoError(t, err)
		require.Equal(t, `{"keys":[{"kty":"OKP","kid":"g1nc0NnN4CMEbdsNL-7X7TFxVtGZsBSTOgp2wuUFx8s","crv":"Ed25519","x":"1W8l-m7roH-0ma4gWUwbbwotRLcPrLkW39zJd5rarnE"}]}`, string(pubRaw))

		pkJWK, err := ToPublicJWKS(pk)
		require.NoError(t, err)
		pkRaw, err := json.Marshal(pkJWK)
		require.NoError(t, err)
		require.Equal(t, `{"keys":[{"kty":"OKP","kid":"g1nc0NnN4CMEbdsNL-7X7TFxVtGZsBSTOgp2wuUFx8s","crv":"Ed25519","x":"1W8l-m7roH-0ma4gWUwbbwotRLcPrLkW39zJd5rarnE"}]}`, string(pkRaw))
	})
}

func TestFromJWK(t *testing.T) {
	t.Parallel()

	t.Run("nil reader", func(t *testing.T) {
		t.Parallel()

		_, err := FromJWK(nil)
		require.Error(t, err)
	})

	t.Run("too large content", func(t *testing.T) {
		t.Parallel()

		_, err := FromJWK(io.LimitReader(rand.Reader, maxJWKLength+1))
		require.Error(t, err)
	})

	t.Run("invalid json", func(t *testing.T) {
		t.Parallel()

		in := strings.NewReader(`{"`)
		out, err := FromJWK(in)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("ED25519", func(t *testing.T) {
		t.Parallel()

		in := strings.NewReader(`{"kty":"OKP","kid":"pLkKHIDVUOtkdhfj6bkmCV29eu61xQOqcwATbfP466c","crv":"Ed25519","x":"bxWBcJu3se8DDSENsY47C6HHdvumXYzarQVBUULRifg","d":"Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk"}`)
		out, err := FromJWK(in)
		require.NoError(t, err)
		require.NotNil(t, out)
		require.Equal(t, "", out.Algorithm)
		require.Equal(t, "pLkKHIDVUOtkdhfj6bkmCV29eu61xQOqcwATbfP466c", out.KeyID)
	})

	t.Run("EC", func(t *testing.T) {
		t.Parallel()

		in := strings.NewReader(`{"kty":"EC","kid":"Omv6VHrsh5UADR4iFyPmMoG5796UpOHYJxcHccNr86A","crv":"P-256","x":"vZ1kpJjwsUocZ6eNxfj6zrWxle7DX5G0P5Mc4vRIKNE","y":"kl2JfGSa_8LTlAV10JbtjRmwkIscaiBCxidYkFdRk5U","d":"N8HEXiXhvByrJ1zKSFT6Y2l2KqDWwWzKf-t4CyWrNKc"}`)
		out, err := FromJWK(in)
		require.NoError(t, err)
		require.NotNil(t, out)
		require.Equal(t, "", out.Algorithm)
		require.Equal(t, "Omv6VHrsh5UADR4iFyPmMoG5796UpOHYJxcHccNr86A", out.KeyID)
	})
}

func TestJWKEncryptionDecryption(t *testing.T) {
	t.Parallel()

	_, pk, err := GenerateKeyPair(ED25519)
	require.NoError(t, err)

	jwk, err := ToJWK(pk)
	require.NoError(t, err)

	// Encrypt the JWK
	jwe, err := ToEncryptedJWK(jwk, []byte("very-secret-password"))
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		// Decrypt
		out, err := FromEncryptedJWK(strings.NewReader(jwe), []byte("very-secret-password"))
		require.NoError(t, err)
		require.Equal(t, pk, out.Key)
	})

	t.Run("invalid secret", func(t *testing.T) {
		t.Parallel()

		out, err := FromEncryptedJWK(strings.NewReader(jwe), []byte("wrong"))
		require.Error(t, err)
		require.Nil(t, out)
	})
}

func TestAttachCertificateToJWK(t *testing.T) {
	t.Parallel()

	caPk, caSk, err := GenerateKeyPair(EC)
	require.NoError(t, err)

	// Generate self-signed CA certificate
	// Should be generated and managed by Vault PKI.
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDERBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, caPk, caSk)
	require.NoError(t, err)

	// Parse the certificate
	caCert, err := x509.ParseCertificate(caDERBytes)
	require.NoError(t, err)

	pk, sk, err := GenerateKeyPair(EC)
	require.NoError(t, err)
	jwk, err := ToJWK(sk)
	require.NoError(t, err)

	// Generate a runner certificate
	runnerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "975ab734-39fd-4015-9a4a-7fd068f3a362.runner.v1.appbuilder.datadoghq.com",
			Organization: []string{"Customer OrgID"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, runnerTemplate, ca, pk, caSk)
	require.NoError(t, err)

	// Parse the certificate
	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	// Attach the runner certificate to the JWK
	require.NoError(t, AttachCertificateToJWK(jwk, cert))
	require.NoError(t, AttachCertificateToJWK(jwk, caCert))

	// Serialize the JWK
	raw, err := json.Marshal(jwk)
	require.NoError(t, err)

	// Deserialize the JWK
	var in jose.JSONWebKey
	require.NoError(t, json.Unmarshal(raw, &in))

	// Check the certificate
	require.Len(t, in.Certificates, 2)
	require.True(t, cert.Equal(in.Certificates[0]))
	require.True(t, caCert.Equal(in.Certificates[1]))
	require.Equal(t, sk, in.Key)

	// Use JWK to sign tokens
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk}, &jose.SignerOptions{
		EmbedJWK: true,
	})
	require.NoError(t, err)

	// Sign a token
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Subject:  "1234567890",
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		Expiry:   jwt.NewNumericDate(time.Now().UTC().Add(time.Hour)),
	}).Serialize()
	require.NoError(t, err)

	// Parse the token
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	require.Len(t, parsed.Headers, 1)

	// Validate certificate
	embeddedJWK := parsed.Headers[0].JSONWebKey
	require.NotNil(t, embeddedJWK)
	require.Len(t, embeddedJWK.Certificates, 2)
	require.True(t, cert.Equal(embeddedJWK.Certificates[0]))
	require.True(t, caCert.Equal(embeddedJWK.Certificates[1]))

	// Validate the embedded certificate against the CA
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	chain, err := embeddedJWK.Certificates[0].Verify(x509.VerifyOptions{
		Roots: caPool,
	})
	require.NoError(t, err)
	require.Len(t, chain, 1)

	// Validate the token using the embedded JWK validated by the CA.
	var claims jwt.Claims
	require.NoError(t, parsed.Claims(embeddedJWK, &claims))
}

func TestAttachCertificateToJWKWithInvalidCertificate(t *testing.T) {
	caPk, caSk, err := GenerateKeyPair(EC)
	require.NoError(t, err)

	// Generate self-signed CA certificate
	// Should be generated and managed by Vault PKI.
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDERBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, caPk, caSk)
	require.NoError(t, err)

	// Parse the certificate
	caCert, err := x509.ParseCertificate(caDERBytes)
	require.NoError(t, err)

	_, sk, err := GenerateKeyPair(EC)
	require.NoError(t, err)
	jwk, err := ToJWK(sk)
	require.NoError(t, err)

	require.Error(t, AttachCertificateToJWK(jwk, caCert))
}

func TestAttachCertificateToJWKWithPublicKeyMismatch(t *testing.T) {
	cpk, csk, err := GenerateKeyPair(EC)
	require.NoError(t, err)

	// Generate self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, cpk, csk)
	require.NoError(t, err)

	// Parse the certificate
	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	_, sk, err := GenerateKeyPair(EC)
	require.NoError(t, err)
	jwk, err := ToJWK(sk)
	require.NoError(t, err)

	require.Error(t, AttachCertificateToJWK(jwk, cert))
}
