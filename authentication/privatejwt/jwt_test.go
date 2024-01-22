package privatejwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

	"github.com/DataDog/go-secure-sdk/crypto/keyutil"
)

func TestRestrictedAssertionVerifier(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	type args struct {
		assertionType string
		key           *jose.JSONWebKey
		clientID      string
		expiration    time.Duration
	}
	tests := []struct {
		name    string
		args    args
		want    Signer
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "blank assertion type",
			args: args{
				assertionType: "   ",
			},
			wantErr: true,
		},
		{
			name: "invalid assertion type syntax",
			args: args{
				assertionType: "!test",
			},
			wantErr: true,
		},
		{
			name: "nil key",
			args: args{
				assertionType: "at",
				key:           nil,
			},
			wantErr: true,
		},
		{
			name: "public key",
			args: args{
				assertionType: "at",
				key: &jose.JSONWebKey{
					Key: pub,
				},
			},
			wantErr: true,
		},
		{
			name: "key not for signature",
			args: args{
				assertionType: "at",
				key: &jose.JSONWebKey{
					Key: priv,
					Use: "enc",
				},
			},
			wantErr: true,
		},
		{
			name: "blank clientID",
			args: args{
				assertionType: "at",
				key: &jose.JSONWebKey{
					Key: priv,
					Use: "sig",
				},
				clientID: "",
			},
			wantErr: true,
		},
		{
			name: "expiration too low",
			args: args{
				assertionType: "at",
				key: &jose.JSONWebKey{
					Key: priv,
					Use: "sig",
				},
				clientID:   "0123456789",
				expiration: minExpiration - 1,
			},
			wantErr: true,
		},
		{
			name: "expiration too large",
			args: args{
				assertionType: "at",
				key: &jose.JSONWebKey{
					Key: priv,
					Use: "sig",
				},
				clientID:   "0123456789",
				expiration: maxExpiration + 1,
			},
			wantErr: true,
		},
		{
			name: "forbidden signature algorithm",
			args: args{
				assertionType: "at",
				key: &jose.JSONWebKey{
					Algorithm: string(jose.HS256),
					Key:       priv,
					Use:       "sig",
				},
				clientID:   "0123456789",
				expiration: 30 * time.Second,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := AssertionSigner(tt.args.assertionType, tt.args.key, tt.args.clientID, tt.args.expiration)
			if (err != nil) != tt.wantErr {
				t.Errorf("AssertionSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AssertionSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAssertionVerifier(t *testing.T) {
	t.Parallel()

	type args struct {
		assertionType string
		clientKeys    ClientKeysResolver
		audience      string
		options       []VerifierOption
	}
	tests := []struct {
		name    string
		args    args
		want    Verifier
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "blank assertion type",
			args: args{
				assertionType: "   ",
			},
			wantErr: true,
		},
		{
			name: "invalid assertion type syntax",
			args: args{
				assertionType: "!test",
			},
			wantErr: true,
		},
		{
			name: "nil client key resolver",
			args: args{
				assertionType: "at",
				clientKeys:    nil,
				audience:      "",
			},
			wantErr: true,
		},
		{
			name: "blank audience",
			args: args{
				assertionType: "at",
				clientKeys:    func(ctx context.Context, id string) ([]*jose.JSONWebKey, error) { return nil, nil },
				audience:      "",
			},
			wantErr: true,
		},
		{
			name: "empty supported algorithm",
			args: args{
				assertionType: "at",
				clientKeys:    func(ctx context.Context, id string) ([]*jose.JSONWebKey, error) { return nil, nil },
				audience:      "https://runner.gw.datadoghq.com",
				options: []VerifierOption{
					WithSupportedAlgorithms([]jose.SignatureAlgorithm{}...),
				},
			},
			wantErr: true,
		},
		{
			name: "not an URL audience",
			args: args{
				assertionType: "at",
				clientKeys:    func(ctx context.Context, id string) ([]*jose.JSONWebKey, error) { return nil, nil },
				audience:      "somewhere",
				options: []VerifierOption{
					WithSupportedAlgorithms(jose.ES256),
				},
			},
			wantErr: true,
		},
		{
			name: "forbidden signature algorithm",
			args: args{
				assertionType: "at",
				clientKeys:    func(ctx context.Context, id string) ([]*jose.JSONWebKey, error) { return nil, nil },
				audience:      "https://runner.gw.datadoghq.com",
				options: []VerifierOption{
					WithSupportedAlgorithms(jose.HS256),
				},
			},
			wantErr: true,
		},
		{
			name: "empty CA pool",
			args: args{
				assertionType: "at",
				clientKeys:    func(ctx context.Context, id string) ([]*jose.JSONWebKey, error) { return nil, nil },
				audience:      "https://runner.gw.datadoghq.com",
				options: []VerifierOption{
					WithSupportedAlgorithms(jose.ES256),
					WithCAPool(x509.NewCertPool()),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := RestrictedAssertionVerifier(tt.args.assertionType, tt.args.audience, tt.args.options...)
			if (err != nil) != tt.wantErr {
				t.Errorf("RestrictedAssertionVerifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RestrictedAssertionVerifier() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAssertionVerifierWithCA(t *testing.T) {
	t.Parallel()

	// Create a CA
	caPk, caSk, err := keyutil.GenerateKeyPair(keyutil.EC)
	require.NoError(t, err)

	// Generate self-signed CA certificate
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

	// Create a client certificate
	clientPk, clientSk, err := keyutil.GenerateKeyPair(keyutil.EC)
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
	derBytes, err := x509.CreateCertificate(rand.Reader, runnerTemplate, ca, clientPk, caSk)
	require.NoError(t, err)

	// Parse the certificate
	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	jwk, err := keyutil.ToJWK(clientSk)
	require.NoError(t, err)

	// Set key usages
	jwk.Use = "sig"
	jwk.Algorithm = string(jose.ES256)

	// Attach the certificate to the private key
	require.NoError(t, keyutil.AttachCertificateToJWK(jwk, cert))

	// Create an assertion signer
	signer, err := AssertionSigner("runner-client", jwk, "123456789", 5*time.Minute)
	require.NoError(t, err)

	// Sign an assertion
	assertion, err := signer.Sign(context.Background(), "https://runner-gw.datadoghq.com")
	require.NoError(t, err)

	// Prepare the CA pool
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// Create a verifier
	verifier, err := RestrictedAssertionVerifier("runner-client", "https://runner-gw.datadoghq.com", WithCAPool(caPool))
	require.NoError(t, err)

	// Verify the assertion
	_, err = verifier.Verify(context.Background(), "123456789", assertion)
	require.NoError(t, err)
}

func TestAssertionVerifierWithInvalidCA(t *testing.T) {
	t.Parallel()

	// Create a CA
	caPk, caSk, err := keyutil.GenerateKeyPair(keyutil.EC)
	require.NoError(t, err)

	// Generate self-signed CA certificate
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

	// Create a self-signed client certificate
	clientPk, clientSk, err := keyutil.GenerateKeyPair(keyutil.EC)
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
	derBytes, err := x509.CreateCertificate(rand.Reader, runnerTemplate, runnerTemplate, clientPk, clientSk)
	require.NoError(t, err)

	// Parse the certificate
	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	jwk, err := keyutil.ToJWK(clientSk)
	require.NoError(t, err)

	// Set key usages
	jwk.Use = "sig"
	jwk.Algorithm = string(jose.ES256)

	// Attach the certificate to the private key
	require.NoError(t, keyutil.AttachCertificateToJWK(jwk, cert))

	// Create an assertion signer
	signer, err := AssertionSigner("runner-client", jwk, "123456789", 5*time.Minute)
	require.NoError(t, err)

	// Sign an assertion
	assertion, err := signer.Sign(context.Background(), "https://runner-gw.datadoghq.com")
	require.NoError(t, err)

	// Prepare the CA pool
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// Create a verifier
	verifier, err := RestrictedAssertionVerifier("runner-client", "https://runner-gw.datadoghq.com", WithCAPool(caPool))
	require.NoError(t, err)

	// Verify the assertion
	_, err = verifier.Verify(context.Background(), "123456789", assertion)
	require.Error(t, err)
}

func BenchmarkAssertionSigner(b *testing.B) {
	b.ReportAllocs()

	var pk jose.JSONWebKey
	require.NoError(b, json.Unmarshal(clientPrivateJWK, &pk))
	signer, err := AssertionSigner("runner-client", &pk, "123456789", 5*time.Minute)
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(context.Background(), "https://runner-gw.datadoghq.com")
		require.NoError(b, err)
	}
}

func BenchmarkAssertionVerifier(b *testing.B) {
	b.ReportAllocs()

	var pk jose.JSONWebKey
	require.NoError(b, json.Unmarshal(clientPrivateJWK, &pk))
	signer, err := AssertionSigner("runner-client", &pk, "123456789", 5*time.Minute)
	require.NoError(b, err)

	assertion, err := signer.Sign(context.Background(), "https://runner-gw.datadoghq.com")
	require.NoError(b, err)

	verifier, err := AssertionVerifier("runner-client", func(ctx context.Context, id string) ([]*jose.JSONWebKey, error) {
		pub := pk.Public()
		return []*jose.JSONWebKey{
			&pub,
		}, nil
	}, "https://runner-gw.datadoghq.com")
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		_, err := verifier.Verify(context.Background(), "123456789", assertion)
		require.NoError(b, err)
	}
}
