package jwt

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/DataDog/go-secure-sdk/crypto/keyutil"
	"github.com/DataDog/go-secure-sdk/crypto/signature"
	sigmock "github.com/DataDog/go-secure-sdk/crypto/signature/test/mock"
	"github.com/DataDog/go-secure-sdk/kms"
	kmsmock "github.com/DataDog/go-secure-sdk/kms/mock"
	"github.com/DataDog/go-secure-sdk/kms/vault"
)

func TestKMSSigner(t *testing.T) {
	t.Parallel()

	t.Run("nil service", func(t *testing.T) {
		t.Parallel()

		s, err := KMSSigner(context.TODO(), nil)
		require.Error(t, err)
		require.Nil(t, s)
	})

	tests := []struct {
		name    string
		prepare func(*kmsmock.MockService)
		want    Signer
		wantErr bool
	}{
		{
			name: "public key error",
			prepare: func(ms *kmsmock.MockService) {
				ms.EXPECT().PublicKey(gomock.Any()).Return(nil, errors.New("test"))
			},
			wantErr: true,
		},
		{
			name: "unsupported public key",
			prepare: func(ms *kmsmock.MockService) {
				ms.EXPECT().PublicKey(gomock.Any()).Return(&rsa.PublicKey{}, nil)
			},
			wantErr: true,
		},
		{
			name: "valid",
			prepare: func(ms *kmsmock.MockService) {
				pub, _, err := keyutil.GenerateDefaultKeyPair()
				require.NoError(t, err)
				ms.EXPECT().PublicKey(gomock.Any()).Return(pub, nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			fakeKMS := kmsmock.NewMockService(ctrl)
			if tt.prepare != nil {
				tt.prepare(fakeKMS)
			}

			got, err := KMSSigner(context.Background(), fakeKMS)
			if (err != nil) != tt.wantErr {
				t.Errorf("KMSSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				require.NotNil(t, got)
			}
		})
	}
}

func Test_kmsSigner_Alg(t *testing.T) {
	t.Parallel()

	ecPub, _, err := keyutil.GenerateKeyPair(keyutil.EC)
	require.NoError(t, err)
	edPub, _, err := keyutil.GenerateKeyPair(keyutil.ED25519)
	require.NoError(t, err)

	ecVerifier, err := signature.FromPublicKey(ecPub)
	require.NoError(t, err)
	edVerifier, err := signature.FromPublicKey(edPub)
	require.NoError(t, err)

	type fields struct {
		ctx      context.Context
		signer   kms.Signer
		verifier signature.Verifier
		pubJwk   jose.JSONWebKey
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "ECDSA P-256",
			fields: fields{
				verifier: ecVerifier,
			},
			want: "ES256",
		},
		{
			name: "Ed25519",
			fields: fields{
				verifier: edVerifier,
			},
			want: "EdDSA",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ts := &kmsSigner{
				ctx:      tt.fields.ctx,
				signer:   tt.fields.signer,
				verifier: tt.fields.verifier,
				pubJwk:   tt.fields.pubJwk,
			}
			if got := ts.Alg(); got != tt.want {
				t.Errorf("kmsSigner.Alg() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_kmsSigner_Sign(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*kmsmock.MockService)
		want    string
		wantErr bool
	}{
		{
			name: "signing error",
			prepare: func(ms *kmsmock.MockService) {
				ms.EXPECT().Sign(gomock.Any(), gomock.Any()).Return(nil, errors.New("test"))
			},
			wantErr: true,
		},
		{
			name: "valid",
			prepare: func(ms *kmsmock.MockService) {
				ms.EXPECT().Sign(gomock.Any(), gomock.Any()).Return([]byte("fake-signature"), nil)
			},
			wantErr: false,
			want:    "fake-signature",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			fakeKMS := kmsmock.NewMockService(ctrl)
			if tt.prepare != nil {
				tt.prepare(fakeKMS)
			}

			ts := &kmsSigner{
				ctx:    context.Background(),
				signer: fakeKMS,
			}
			got, err := ts.Sign("protected", nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("kmsSigner.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("kmsSigner.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_kmsSigner_Verify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*sigmock.MockVerifier)
		wantErr bool
	}{
		{
			name: "verifier error",
			prepare: func(mv *sigmock.MockVerifier) {
				mv.EXPECT().Verify(gomock.Any(), gomock.Any()).Return(errors.New("test"))
			},
			wantErr: true,
		},
		{
			name: "valid",
			prepare: func(mv *sigmock.MockVerifier) {
				mv.EXPECT().Verify(gomock.Any(), gomock.Any()).Return(nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			fakeVerifier := sigmock.NewMockVerifier(ctrl)
			if tt.prepare != nil {
				tt.prepare(fakeVerifier)
			}

			ts := &kmsSigner{
				verifier: fakeVerifier,
			}
			if err := ts.Verify("protected", "OAC3aQKoy5ugP1HIpLkG27BkghiT15fgeDt_-JurJ--52uCVNrmTJih7iLrJkn9srjN1U6xVYmy1ibyRXJcLDw", nil); (err != nil) != tt.wantErr {
				t.Errorf("kmsSigner.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

//nolint:paralleltest // bad behaviour with httptest
func TestService_Ed25519Key(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/transit/keys/ed25519-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"99feec4a-7d86-81d7-5725-8880580488cd","lease_id":"","renewable":false,"lease_duration":0,"data":{"allow_plaintext_backup":false,"auto_rotate_period":0,"deletion_allowed":false,"derived":false,"exportable":false,"imported_key":false,"keys":{"1":{"creation_time":"2022-10-20T14:08:57.409038+02:00","name":"ed25519","public_key":"p09b9LRhAwGvfXXey62lrlLmlI0e8Gt8QAIe5oci11A="}},"latest_version":1,"min_available_version":0,"min_decryption_version":1,"min_encryption_version":0,"name":"ed25519-key","supports_decryption":false,"supports_derivation":true,"supports_encryption":false,"supports_signing":true,"type":"ed25519"},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/sign/ed25519-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"39299d3f-8e8e-f1ea-add7-d7c92d28c750","lease_id":"","renewable":false,"lease_duration":0,"data":{"key_version":1,"signature":"vault:v1:OAC3aQKoy5ugP1HIpLkG27BkghiT15fgeDt_-JurJ--52uCVNrmTJih7iLrJkn9srjN1U6xVYmy1ibyRXJcLDw"},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/verify/ed25519-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"2ded8d72-088c-9258-3999-05a00f8f1144","lease_id":"","renewable":false,"lease_duration":0,"data":{"batch_results":[{"valid":true}]},"wrap_info":null,"warnings":null,"auth":null}`)
		default:
			w.WriteHeader(400)
		}
	}))
	t.Cleanup(func() {
		server.Close()
	})

	// Initialize Vault client
	vaultClient, err := api.NewClient(&api.Config{
		Address:    server.URL,
		Timeout:    time.Second * 5,
		MaxRetries: 1,
		HttpClient: &http.Client{Transport: cleanhttp.DefaultTransport(), Timeout: time.Second * 10},
	})
	if err != nil {
		t.Fatal(err)
	}

	kmsService, err := vault.New(ctx, vaultClient, "transit", "ed25519-key")
	assert.NoError(t, err)

	underTest, err := KMSSigner(ctx, kmsService)
	assert.NoError(t, err)
	assert.NotNil(t, underTest)

	t.Run("Sign", func(t *testing.T) {
		got, err := underTest.Sign("protected", nil)
		assert.NoError(t, err)
		assert.Equal(t, "OAC3aQKoy5ugP1HIpLkG27BkghiT15fgeDt_-JurJ--52uCVNrmTJih7iLrJkn9srjN1U6xVYmy1ibyRXJcLDw", got)
	})

	t.Run("Verify", func(t *testing.T) {
		err := underTest.Verify("protected", "OAC3aQKoy5ugP1HIpLkG27BkghiT15fgeDt_-JurJ--52uCVNrmTJih7iLrJkn9srjN1U6xVYmy1ibyRXJcLDw", nil)
		assert.NoError(t, err)
	})
}
