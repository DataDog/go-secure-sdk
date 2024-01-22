package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"

	"github.com/DataDog/go-secure-sdk/kms/vault/logical"
)

func Test_service_Encrypt(t *testing.T) {
	t.Parallel()

	type args struct {
		ctx       context.Context
		cleartext []byte
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*logical.MockLogical)
		want    []byte
		wantErr bool
	}{
		{
			name: "nil",
			args: args{
				ctx:       context.Background(),
				cleartext: nil,
			},
			wantErr: true,
		},
		{
			name: "write error",
			args: args{
				ctx:       context.Background(),
				cleartext: []byte("my secret data"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/encrypt/test-key", gomock.Any()).Return(nil, errors.New("test"))
			},
			wantErr: true,
		},
		{
			name: "response without data",
			args: args{
				ctx:       context.Background(),
				cleartext: []byte("my secret data"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/encrypt/test-key", gomock.Any()).Return(&api.Secret{}, nil)
			},
			wantErr: true,
		},
		{
			name: "response with empty data",
			args: args{
				ctx:       context.Background(),
				cleartext: []byte("my secret data"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/encrypt/test-key", gomock.Any()).Return(&api.Secret{
					Data: map[string]interface{}{},
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "response with blank ciphertext",
			args: args{
				ctx:       context.Background(),
				cleartext: []byte("my secret data"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/encrypt/test-key", gomock.Any()).Return(&api.Secret{
					Data: map[string]interface{}{
						"ciphertext": "",
					},
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				ctx:       context.Background(),
				cleartext: []byte("my secret data"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/encrypt/test-key", gomock.Any()).Return(&api.Secret{
					Data: map[string]interface{}{
						"ciphertext": "vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w==",
					},
				}, nil)
			},
			wantErr: false,
			want:    []byte("8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w=="),
		},
	}
	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			logicalMock := logical.NewMockLogical(ctrl)

			// Prepare mocks
			if tt.prepare != nil {
				tt.prepare(logicalMock)
			}

			underTest := &service{
				logical:     logicalMock,
				mountPath:   "transit",
				keyName:     "test-key",
				canEncrypt:  true,
				lastVersion: 1,
			}

			got, err := underTest.Encrypt(tt.args.ctx, tt.args.cleartext)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("service.Encrypt() = %s, want %s", got, tt.want)
			}
		})
	}
}

func Test_service_Decrypt(t *testing.T) {
	t.Parallel()

	type args struct {
		ctx        context.Context
		ciphertext []byte
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*logical.MockLogical)
		want    []byte
		wantErr bool
	}{
		{
			name: "nil",
			args: args{
				ctx:        context.Background(),
				ciphertext: nil,
			},
			wantErr: true,
		},
		{
			name: "write error",
			args: args{
				ctx:        context.Background(),
				ciphertext: []byte("vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w=="),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/decrypt/test-key", gomock.Any()).Return(nil, errors.New("test"))
			},
			wantErr: true,
		},
		{
			name: "response without data",
			args: args{
				ctx:        context.Background(),
				ciphertext: []byte("vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w=="),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/decrypt/test-key", gomock.Any()).Return(&api.Secret{}, nil)
			},
			wantErr: true,
		},
		{
			name: "response with empty data",
			args: args{
				ctx:        context.Background(),
				ciphertext: []byte("vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w=="),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/decrypt/test-key", gomock.Any()).Return(&api.Secret{
					Data: map[string]interface{}{},
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "response with blank plaintext",
			args: args{
				ctx:        context.Background(),
				ciphertext: []byte("vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w=="),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/decrypt/test-key", gomock.Any()).Return(&api.Secret{
					Data: map[string]interface{}{
						"plaintext": "",
					},
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "response with invalid plaintext base64",
			args: args{
				ctx:        context.Background(),
				ciphertext: []byte("vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w=="),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/decrypt/test-key", gomock.Any()).Return(&api.Secret{
					Data: map[string]interface{}{
						"plaintext": "123",
					},
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				ctx:        context.Background(),
				ciphertext: []byte("vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w=="),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/decrypt/test-key", gomock.Any()).Return(&api.Secret{
					Data: map[string]interface{}{
						"plaintext": "bXkgc2VjcmV0IGRhdGE=",
					},
				}, nil)
			},
			wantErr: false,
			want:    []byte("my secret data"),
		},
	}
	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			logicalMock := logical.NewMockLogical(ctrl)

			// Prepare mocks
			if tt.prepare != nil {
				tt.prepare(logicalMock)
			}

			underTest := &service{
				logical:     logicalMock,
				mountPath:   "transit",
				keyName:     "test-key",
				canDecrypt:  true,
				lastVersion: 1,
			}

			got, err := underTest.Decrypt(tt.args.ctx, tt.args.ciphertext)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("service.Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_service_Sign(t *testing.T) {
	t.Parallel()

	type args struct {
		ctx       context.Context
		protected []byte
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*logical.MockLogical)
		want    []byte
		wantErr bool
	}{
		{
			name: "nil",
			args: args{
				ctx:       context.Background(),
				protected: nil,
			},
			wantErr: true,
		},
		{
			name: "write error",
			args: args{
				ctx:       context.Background(),
				protected: []byte("my secret data"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/sign/test-key", gomock.Any()).Return(nil, errors.New("test"))
			},
			wantErr: true,
		},
		{
			name: "response without data",
			args: args{
				ctx:       context.Background(),
				protected: []byte("my secret data"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/sign/test-key", gomock.Any()).Return(&api.Secret{}, nil)
			},
			wantErr: true,
		},
		{
			name: "response with empty data",
			args: args{
				ctx:       context.Background(),
				protected: []byte("my secret data"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/sign/test-key", gomock.Any()).Return(&api.Secret{
					Data: map[string]interface{}{},
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "response with blank signature",
			args: args{
				ctx:       context.Background(),
				protected: []byte("my secret data"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/sign/test-key", gomock.Any()).Return(&api.Secret{
					Data: map[string]interface{}{
						"signature": "",
					},
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				ctx:       context.Background(),
				protected: []byte("my secret data"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/sign/test-key", gomock.Any()).Return(&api.Secret{
					Data: map[string]interface{}{
						"signature": "vault:v1:cCmvd0rMDvLhLJtl6fjzdtWPfCt3FEgEzM9ViTmByEqeHh6V40aYBEml4Ef14gbEIYMCipt-sTWbHCSBqx_N_JTA6n4Sjx0vN60bhlPCdKr8KaD2g_Rokq_R4nHHlrUBuC1Kp45zCC-nyNHpLwlqcPdL4A0GlCrbMpLmml308Ht47Q7R83Yg5ww0oGy7EoTNnhoDX46FWOvueaUCClhmUCtIJkSvqAJKyqQFavgsyWc2ahVFR53FFk_aY9S5Z3uW9qMF5Lr-UymPsSB8CHmGtfURMZHWooB1N0r5aPLwr-ieQu0vOXXKRI88YpzXGaRy05rlT9ygpjdWRDs-OHFK3A",
					},
				}, nil)
			},
			wantErr: false,
			want:    []byte("cCmvd0rMDvLhLJtl6fjzdtWPfCt3FEgEzM9ViTmByEqeHh6V40aYBEml4Ef14gbEIYMCipt-sTWbHCSBqx_N_JTA6n4Sjx0vN60bhlPCdKr8KaD2g_Rokq_R4nHHlrUBuC1Kp45zCC-nyNHpLwlqcPdL4A0GlCrbMpLmml308Ht47Q7R83Yg5ww0oGy7EoTNnhoDX46FWOvueaUCClhmUCtIJkSvqAJKyqQFavgsyWc2ahVFR53FFk_aY9S5Z3uW9qMF5Lr-UymPsSB8CHmGtfURMZHWooB1N0r5aPLwr-ieQu0vOXXKRI88YpzXGaRy05rlT9ygpjdWRDs-OHFK3A"),
		},
	}
	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			logicalMock := logical.NewMockLogical(ctrl)

			// Prepare mocks
			if tt.prepare != nil {
				tt.prepare(logicalMock)
			}

			underTest := &service{
				logical:     logicalMock,
				mountPath:   "transit",
				keyName:     "test-key",
				canSign:     true,
				lastVersion: 1,
			}

			got, err := underTest.Sign(tt.args.ctx, tt.args.protected)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("service.Sign() = %s, want %s", got, tt.want)
			}
		})
	}
}

func Test_service_Verify(t *testing.T) {
	t.Parallel()

	type args struct {
		ctx       context.Context
		protected []byte
		signature []byte
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*logical.MockLogical)
		wantErr bool
	}{
		{
			name: "nil",
			args: args{
				ctx:       context.Background(),
				protected: nil,
				signature: nil,
			},
			wantErr: true,
		},
		{
			name: "nil protected",
			args: args{
				ctx:       context.Background(),
				protected: nil,
				signature: []byte("fake-signature"),
			},
			wantErr: true,
		},
		{
			name: "nil signature",
			args: args{
				ctx:       context.Background(),
				protected: []byte("my secret data"),
				signature: nil,
			},
			wantErr: true,
		},
		{
			name: "write error",
			args: args{
				ctx:       context.Background(),
				protected: []byte("my secret data"),
				signature: []byte("fake-signature"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/verify/test-key", gomock.Any()).Return(nil, errors.New("test"))
			},
			wantErr: true,
		},
		{
			name: "response without data",
			args: args{
				ctx:       context.Background(),
				protected: []byte("my secret data"),
				signature: []byte("fake-signature"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/verify/test-key", gomock.Any()).Return(&api.Secret{}, nil)
			},
			wantErr: true,
		},
		{
			name: "response with empty data",
			args: args{
				ctx:       context.Background(),
				protected: []byte("my secret data"),
				signature: []byte("fake-signature"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/verify/test-key", gomock.Any()).Return(&api.Secret{
					Data: map[string]interface{}{},
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "response with invalid type",
			args: args{
				ctx:       context.Background(),
				protected: []byte("my secret data"),
				signature: []byte("fake-signature"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/verify/test-key", gomock.Any()).Return(&api.Secret{
					Data: map[string]interface{}{
						"valid": 8,
					},
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "response with invalid status",
			args: args{
				ctx:       context.Background(),
				protected: []byte("my secret data"),
				signature: []byte("fake-signature"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/verify/test-key", gomock.Any()).Return(&api.Secret{
					Data: map[string]interface{}{
						"valid": false,
					},
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				ctx:       context.Background(),
				protected: []byte("my secret data"),
				signature: []byte("fake-signature"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/verify/test-key", gomock.Any()).Return(&api.Secret{
					Data: map[string]interface{}{
						"batch_results": []any{
							map[string]any{
								"valid": true,
							},
						},
					},
				}, nil)
			},
			wantErr: false,
		},
	}
	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			logicalMock := logical.NewMockLogical(ctrl)

			// Prepare mocks
			if tt.prepare != nil {
				tt.prepare(logicalMock)
			}

			underTest := &service{
				logical:     logicalMock,
				mountPath:   "transit",
				keyName:     "test-key",
				canSign:     true,
				lastVersion: 1,
			}

			err := underTest.Verify(tt.args.ctx, tt.args.protected, tt.args.signature)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

//nolint:paralleltest // bad behaviour with httptest
func TestService_NotFound(t *testing.T) {
	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/transit/keys/not-found":
			w.WriteHeader(404)
			fmt.Fprintln(w, `{"errors":[]}`)
		default:
			w.WriteHeader(400)
		}
	}))
	defer server.Close()

	// Initialize Vault client
	vaultClient, err := api.NewClient(&api.Config{
		Address:    server.URL,
		Timeout:    time.Second * 1,
		MaxRetries: 1,
		HttpClient: &http.Client{Transport: cleanhttp.DefaultTransport(), Timeout: time.Second * 2},
	})
	if err != nil {
		t.Fatal(err)
	}

	underTest, err := New(context.Background(), vaultClient, "transit", "not-found")
	assert.Error(t, err)
	assert.Nil(t, underTest)
}

//nolint:paralleltest // bad behaviour with httptest
func TestService_SymmetricKey(t *testing.T) {
	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/transit/keys/symmetric-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"bca23031-0ea7-4789-b9b3-70746bdbad25","lease_id":"","renewable":false,"lease_duration":0,"data":{"allow_plaintext_backup":false,"auto_rotate_period":0,"deletion_allowed":false,"derived":false,"exportable":false,"imported_key":false,"keys":{"1":1666264701},"latest_version":1,"min_available_version":0,"min_decryption_version":1,"min_encryption_version":0,"name":"symmetric-key","supports_decryption":true,"supports_derivation":true,"supports_encryption":true,"supports_signing":false,"type":"aes256-gcm96"},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/encrypt/symmetric-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"2c6f505c-6ee9-eef9-5f01-024e7285dfdd","lease_id":"","renewable":false,"lease_duration":0,"data":{"ciphertext":"vault:v1:xZreiIykBIhPRcrjgpAxledDkdZFF0TzyiKUwUU1/3E=","key_version":1},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/decrypt/symmetric-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"1941f278-8d6c-89f8-5311-17461db8a8e5","lease_id":"","renewable":false,"lease_duration":0,"data":{"plaintext":"dGVzdA=="},"wrap_info":null,"warnings":null,"auth":null}`)
		default:
			w.WriteHeader(400)
		}
	}))
	defer server.Close()

	// Initialize Vault client
	vaultClient, err := api.NewClient(&api.Config{
		Address:    server.URL,
		Timeout:    time.Second * 1,
		MaxRetries: 1,
		HttpClient: &http.Client{Transport: cleanhttp.DefaultTransport(), Timeout: time.Second * 2},
	})
	if err != nil {
		t.Fatal(err)
	}

	underTest, err := New(context.Background(), vaultClient, "transit", "symmetric-key")
	assert.NoError(t, err)
	assert.NotNil(t, underTest)

	t.Run("Encrypt", func(t *testing.T) {
		got, err := underTest.Encrypt(context.Background(), []byte("test"))
		assert.NoError(t, err)
		assert.Equal(t, []byte("xZreiIykBIhPRcrjgpAxledDkdZFF0TzyiKUwUU1/3E="), got)
	})

	t.Run("Decrypt", func(t *testing.T) {
		got, err := underTest.Decrypt(context.Background(), []byte("xZreiIykBIhPRcrjgpAxledDkdZFF0TzyiKUwUU1/3E="))
		assert.NoError(t, err)
		assert.Equal(t, []byte("test"), got)
	})

	t.Run("Public", func(t *testing.T) {
		pub, err := underTest.PublicKey(context.Background())
		assert.Error(t, err)
		assert.ErrorContains(t, err, "the key doesn't have a public key")
		assert.Nil(t, pub)
	})

	t.Run("Sign", func(t *testing.T) {
		got, err := underTest.Sign(context.Background(), []byte{})
		assert.Error(t, err)
		assert.ErrorContains(t, err, "sign operation is not supported by the key")
		assert.Nil(t, got)
	})

	t.Run("Verify", func(t *testing.T) {
		err := underTest.Verify(context.Background(), []byte{}, []byte{})
		assert.Error(t, err)
		assert.ErrorContains(t, err, "verify operation is not supported by the key")
	})
}

//nolint:paralleltest // bad behaviour with httptest
func TestService_RSAKey(t *testing.T) {
	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/transit/keys/rsa-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"965c5b61-6067-4e2b-d976-910d3a49e8b7","lease_id":"","renewable":false,"lease_duration":0,"data":{"allow_plaintext_backup":false,"auto_rotate_period":0,"deletion_allowed":false,"derived":false,"exportable":false,"imported_key":false,"keys":{"1":{"creation_time":"2022-10-20T13:36:14.593595+02:00","name":"rsa-2048","public_key":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5wtsZWhlgK6T19TnTh/H\nIn3CTDVaAKUYmzHtLBo8uzl0rXSfnfWZrdLM8oGDib/N/iIJTfk5V3HeuH8tzqw8\nWQAXBjvpZwDjIlvBf+AcCPEFkmgYKgsSzDQFX4IroIQgM8lPR/cxZ4qnqsWxBIXy\nYdN53Y/sa+SrPsJKDh2eX1Yzx52fqz1BvZJufUySgNPwQCHlCsLMI6RiLFKwRw/K\nFpGBynqYQZKAKlYgAL1UAxfjQdfBFrymBS+eNAfXp0bn8q/U5O3jSlepiirebg8c\nODlNquihYK4SlJmAcf3pqPj+CTwzpYXc1D1HYWL+Egvl52ZzkZIbHzHp6oL1AYRu\nAQIDAQAB\n-----END PUBLIC KEY-----\n"}},"latest_version":1,"min_available_version":0,"min_decryption_version":1,"min_encryption_version":0,"name":"rsa-key","supports_decryption":true,"supports_derivation":false,"supports_encryption":true,"supports_signing":true,"type":"rsa-2048"},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/encrypt/rsa-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"6067c3c8-cb27-2551-53ef-e73bd2b430a3","lease_id":"","renewable":false,"lease_duration":0,"data":{"ciphertext":"vault:v1:XnYNMfJIkKWSS+EZYd3k+zON/G0/ld/00aaXUCzEQ5Ka2kfLgzPeHxSSKWUeA88kwzKFYuzmGohvpNdwCnYN/tHubJKDt1RR4sfO5bFpT8WlaGlDNkbWJkfjVu4QdgGdEqUIr2kfS4BFumAxbhBSJQWlzx3yjUl1KODe41iM7E6RBxZnBLcHzOVGM4Ly18wGokB//rPiA7bFZ1L1fMdQhpYw7vBihKViUz6kG9bJuX1vzUP2VIl0Oa+5fhsUIf/6bs0VOKzkQ/Yjx3S30eptIG1XPZALA0C+TeNj99wpGVB9t60Sh/wuIRLXNadO+fbSoSE1KIv1maEKfE8zvOF7sg==","key_version":1},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/decrypt/rsa-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"bee00e75-e8c5-dc70-f718-42bfa864020f","lease_id":"","renewable":false,"lease_duration":0,"data":{"plaintext":"dGVzdA=="},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/sign/rsa-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"9f84bf14-4e43-1797-1da9-2045e4b1b84c","lease_id":"","renewable":false,"lease_duration":0,"data":{"key_version":1,"signature":"vault:v1:cCmvd0rMDvLhLJtl6fjzdtWPfCt3FEgEzM9ViTmByEqeHh6V40aYBEml4Ef14gbEIYMCipt-sTWbHCSBqx_N_JTA6n4Sjx0vN60bhlPCdKr8KaD2g_Rokq_R4nHHlrUBuC1Kp45zCC-nyNHpLwlqcPdL4A0GlCrbMpLmml308Ht47Q7R83Yg5ww0oGy7EoTNnhoDX46FWOvueaUCClhmUCtIJkSvqAJKyqQFavgsyWc2ahVFR53FFk_aY9S5Z3uW9qMF5Lr-UymPsSB8CHmGtfURMZHWooB1N0r5aPLwr-ieQu0vOXXKRI88YpzXGaRy05rlT9ygpjdWRDs-OHFK3A"},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/verify/rsa-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"a8aa936f-c8e1-a957-026e-2236d5a9b31e","lease_id":"","renewable":false,"lease_duration":0,"data":{"batch_results":[{"valid":true}]},"wrap_info":null,"warnings":null,"auth":null}`)
		default:
			w.WriteHeader(400)
		}
	}))
	defer server.Close()

	// Initialize Vault client
	vaultClient, err := api.NewClient(&api.Config{
		Address:    server.URL,
		Timeout:    time.Second * 1,
		MaxRetries: 1,
		HttpClient: &http.Client{Transport: cleanhttp.DefaultTransport(), Timeout: time.Second * 2},
	})
	if err != nil {
		t.Fatal(err)
	}

	underTest, err := New(context.Background(), vaultClient, "transit", "rsa-key")
	assert.NoError(t, err)
	assert.NotNil(t, underTest)

	t.Run("Encrypt", func(t *testing.T) {
		got, err := underTest.Encrypt(context.Background(), []byte("test"))
		assert.NoError(t, err)
		assert.Equal(t, []byte("XnYNMfJIkKWSS+EZYd3k+zON/G0/ld/00aaXUCzEQ5Ka2kfLgzPeHxSSKWUeA88kwzKFYuzmGohvpNdwCnYN/tHubJKDt1RR4sfO5bFpT8WlaGlDNkbWJkfjVu4QdgGdEqUIr2kfS4BFumAxbhBSJQWlzx3yjUl1KODe41iM7E6RBxZnBLcHzOVGM4Ly18wGokB//rPiA7bFZ1L1fMdQhpYw7vBihKViUz6kG9bJuX1vzUP2VIl0Oa+5fhsUIf/6bs0VOKzkQ/Yjx3S30eptIG1XPZALA0C+TeNj99wpGVB9t60Sh/wuIRLXNadO+fbSoSE1KIv1maEKfE8zvOF7sg=="), got)
	})

	t.Run("Decrypt", func(t *testing.T) {
		got, err := underTest.Decrypt(context.Background(), []byte("XnYNMfJIkKWSS+EZYd3k+zON/G0/ld/00aaXUCzEQ5Ka2kfLgzPeHxSSKWUeA88kwzKFYuzmGohvpNdwCnYN/tHubJKDt1RR4sfO5bFpT8WlaGlDNkbWJkfjVu4QdgGdEqUIr2kfS4BFumAxbhBSJQWlzx3yjUl1KODe41iM7E6RBxZnBLcHzOVGM4Ly18wGokB//rPiA7bFZ1L1fMdQhpYw7vBihKViUz6kG9bJuX1vzUP2VIl0Oa+5fhsUIf/6bs0VOKzkQ/Yjx3S30eptIG1XPZALA0C+TeNj99wpGVB9t60Sh/wuIRLXNadO+fbSoSE1KIv1maEKfE8zvOF7sg=="))
		assert.NoError(t, err)
		assert.Equal(t, []byte("test"), got)
	})

	t.Run("Public", func(t *testing.T) {
		pub, err := underTest.PublicKey(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, pub)
	})

	t.Run("Sign", func(t *testing.T) {
		got, err := underTest.Sign(context.Background(), []byte("protected"))
		assert.NoError(t, err)
		assert.Equal(t, []byte("cCmvd0rMDvLhLJtl6fjzdtWPfCt3FEgEzM9ViTmByEqeHh6V40aYBEml4Ef14gbEIYMCipt-sTWbHCSBqx_N_JTA6n4Sjx0vN60bhlPCdKr8KaD2g_Rokq_R4nHHlrUBuC1Kp45zCC-nyNHpLwlqcPdL4A0GlCrbMpLmml308Ht47Q7R83Yg5ww0oGy7EoTNnhoDX46FWOvueaUCClhmUCtIJkSvqAJKyqQFavgsyWc2ahVFR53FFk_aY9S5Z3uW9qMF5Lr-UymPsSB8CHmGtfURMZHWooB1N0r5aPLwr-ieQu0vOXXKRI88YpzXGaRy05rlT9ygpjdWRDs-OHFK3A"), got)
	})

	t.Run("Verify", func(t *testing.T) {
		err := underTest.Verify(context.Background(), []byte("protected"), []byte("cCmvd0rMDvLhLJtl6fjzdtWPfCt3FEgEzM9ViTmByEqeHh6V40aYBEml4Ef14gbEIYMCipt-sTWbHCSBqx_N_JTA6n4Sjx0vN60bhlPCdKr8KaD2g_Rokq_R4nHHlrUBuC1Kp45zCC-nyNHpLwlqcPdL4A0GlCrbMpLmml308Ht47Q7R83Yg5ww0oGy7EoTNnhoDX46FWOvueaUCClhmUCtIJkSvqAJKyqQFavgsyWc2ahVFR53FFk_aY9S5Z3uW9qMF5Lr-UymPsSB8CHmGtfURMZHWooB1N0r5aPLwr-ieQu0vOXXKRI88YpzXGaRy05rlT9ygpjdWRDs-OHFK3A"))
		assert.NoError(t, err)
	})
}

//nolint:paralleltest // bad behaviour with httptest
func TestService_ECKey(t *testing.T) {
	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/transit/keys/ec-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"b731acfa-3d3a-fb3c-a303-29c16ef52a04","lease_id":"","renewable":false,"lease_duration":0,"data":{"allow_plaintext_backup":false,"auto_rotate_period":0,"deletion_allowed":false,"derived":false,"exportable":false,"imported_key":false,"keys":{"1":{"creation_time":"2022-10-20T13:58:33.086128+02:00","name":"P-256","public_key":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5479CR3hp9ZUpki56R7AC3V5yY5z\nZLixQgTrGVl+NSdeF1Ec21uN/KFwtRFdali9gzCRy9eWNWT/ICrxOzbMEg==\n-----END PUBLIC KEY-----\n"}},"latest_version":1,"min_available_version":0,"min_decryption_version":1,"min_encryption_version":0,"name":"ec-key","supports_decryption":false,"supports_derivation":false,"supports_encryption":false,"supports_signing":true,"type":"ecdsa-p256"},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/sign/ec-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"ea1c1983-3bd5-c30a-afae-baeeec788b9a","lease_id":"","renewable":false,"lease_duration":0,"data":{"key_version":1,"signature":"vault:v1:NcCkFNYih3xtL0aDfY5OycWV_wMEJSbZXltusG_aTWY4FT8lEjBprARyRgT9Z_ZbTbOAlwvELOJ-OmlgwzfI0A"},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/verify/ec-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"44457b9a-6fd1-d756-1d0a-fe4c102d13d9","lease_id":"","renewable":false,"lease_duration":0,"data":{"batch_results":[{"valid":true}]},"wrap_info":null,"warnings":null,"auth":null}`)
		default:
			w.WriteHeader(400)
		}
	}))
	defer server.Close()

	// Initialize Vault client
	vaultClient, err := api.NewClient(&api.Config{
		Address:    server.URL,
		Timeout:    time.Second * 1,
		MaxRetries: 1,
		HttpClient: &http.Client{Transport: cleanhttp.DefaultTransport(), Timeout: time.Second * 2},
	})
	if err != nil {
		t.Fatal(err)
	}

	underTest, err := New(context.Background(), vaultClient, "transit", "ec-key")
	assert.NoError(t, err)
	assert.NotNil(t, underTest)

	t.Run("Encrypt", func(t *testing.T) {
		got, err := underTest.Encrypt(context.Background(), []byte(""))
		assert.Error(t, err)
		assert.ErrorContains(t, err, "encrypt operation is not supported by the key")
		assert.Nil(t, got)
	})

	t.Run("Decrypt", func(t *testing.T) {
		got, err := underTest.Decrypt(context.Background(), []byte(""))
		assert.Error(t, err)
		assert.ErrorContains(t, err, "decrypt operation is not supported by the key")
		assert.Nil(t, got)
	})

	t.Run("Public", func(t *testing.T) {
		pub, err := underTest.PublicKey(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, pub)
	})

	t.Run("Sign", func(t *testing.T) {
		got, err := underTest.Sign(context.Background(), []byte("protected"))
		assert.NoError(t, err)
		assert.Equal(t, []byte("NcCkFNYih3xtL0aDfY5OycWV_wMEJSbZXltusG_aTWY4FT8lEjBprARyRgT9Z_ZbTbOAlwvELOJ-OmlgwzfI0A"), got)
	})

	t.Run("Verify", func(t *testing.T) {
		err := underTest.Verify(context.Background(), []byte("protected"), []byte("NcCkFNYih3xtL0aDfY5OycWV_wMEJSbZXltusG_aTWY4FT8lEjBprARyRgT9Z_ZbTbOAlwvELOJ-OmlgwzfI0A"))
		assert.NoError(t, err)
	})
}

//nolint:paralleltest // bad behaviour with httptest
func TestService_Ed25519Key(t *testing.T) {
	t.Parallel()

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
	defer server.Close()

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

	underTest, err := New(context.Background(), vaultClient, "transit", "ed25519-key")
	assert.NoError(t, err)
	assert.NotNil(t, underTest)

	t.Run("Encrypt", func(t *testing.T) {
		got, err := underTest.Encrypt(context.Background(), []byte(""))
		assert.Error(t, err)
		assert.ErrorContains(t, err, "encrypt operation is not supported by the key")
		assert.Nil(t, got)
	})

	t.Run("Decrypt", func(t *testing.T) {
		got, err := underTest.Decrypt(context.Background(), []byte(""))
		assert.Error(t, err)
		assert.ErrorContains(t, err, "decrypt operation is not supported by the key")
		assert.Nil(t, got)
	})

	t.Run("Public", func(t *testing.T) {
		pub, err := underTest.PublicKey(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, pub)
	})

	t.Run("Sign", func(t *testing.T) {
		got, err := underTest.Sign(context.Background(), []byte("protected"))
		assert.NoError(t, err)
		assert.Equal(t, []byte("OAC3aQKoy5ugP1HIpLkG27BkghiT15fgeDt_-JurJ--52uCVNrmTJih7iLrJkn9srjN1U6xVYmy1ibyRXJcLDw"), got)
	})

	t.Run("Verify", func(t *testing.T) {
		err := underTest.Verify(context.Background(), []byte("protected"), []byte("OAC3aQKoy5ugP1HIpLkG27BkghiT15fgeDt_-JurJ--52uCVNrmTJih7iLrJkn9srjN1U6xVYmy1ibyRXJcLDw"))
		assert.NoError(t, err)
	})
}
