package vault

import (
	"context"
	"crypto"
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

	"github.com/DataDog/go-secure-sdk/kms"
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
			name: "nil response",
			args: args{
				ctx:       context.Background(),
				cleartext: []byte("my secret data"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/encrypt/test-key", gomock.Any()).Return(nil, nil)
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
			name: "nil response",
			args: args{
				ctx:        context.Background(),
				ciphertext: []byte("vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w=="),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/decrypt/test-key", gomock.Any()).Return(nil, nil)
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
			name: "nil response",
			args: args{
				ctx:       context.Background(),
				protected: []byte("my secret data"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/sign/test-key", gomock.Any()).Return(nil, nil)
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
			name: "nil response",
			args: args{
				ctx:       context.Background(),
				protected: []byte("my secret data"),
				signature: []byte("fake-signature"),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/verify/test-key", gomock.Any()).Return(nil, nil)
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

func Test_service_RotateKey(t *testing.T) {
	t.Parallel()

	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*logical.MockLogical)
		wantErr bool
	}{
		{
			name: "write error",
			args: args{
				ctx: context.Background(),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/keys/test-key/rotate", gomock.Any()).Return(nil, errors.New("test"))
			},
			wantErr: true,
		},
		{
			name: "nil response",
			args: args{
				ctx: context.Background(),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/keys/test-key/rotate", gomock.Any()).Return(nil, nil)
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().WriteWithContext(gomock.Any(), "transit/keys/test-key/rotate", gomock.Any()).Return(&api.Secret{}, nil)
				ml.EXPECT().ReadWithContext(gomock.Any(), "transit/keys/test-key").Return(&api.Secret{
					Data: map[string]interface{}{
						"exportable": true,
						"keys": map[string]interface{}{
							"1": map[string]interface{}{
								"creation_time": "2023-10-20T13:22:55.218283+02:00",
								"name":          "ed25519",
								"public_key":    "rWNIKBkLV1FC4+68s1jOLFHq+oC7yisn3HIQQcTk5Bg=",
							},
							"2": map[string]interface{}{
								"creation_time": "2023-10-20T13:34:01.09267+02:00",
								"name":          "ed25519",
								"public_key":    "NYNTJzwTy+shbISb86cWRcyzYCxjO9MoyGSohXironk=",
							},
						},
						"latest_version":         2,
						"min_available_version":  0,
						"min_decryption_version": 1,
						"min_encryption_version": 0,
						"name":                   "ed25519-key",
						"supports_decryption":    false,
						"supports_derivation":    true,
						"supports_encryption":    false,
						"supports_signing":       true,
						"type":                   "ed25519",
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
				keyType:     kms.KeyTypeECDSA,
				publicKeys:  map[int]crypto.PublicKey{},
			}

			err := underTest.RotateKey(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Rotate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_service_ExportKey(t *testing.T) {
	t.Parallel()

	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*logical.MockLogical)
		wantRaw string
		wantKty kms.KeyType
		wantErr bool
	}{
		{
			name: "write error",
			args: args{
				ctx: context.Background(),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().ReadWithContext(gomock.Any(), "transit/export/signing-key/test-key/2").Return(nil, errors.New("test"))
			},
			wantErr: true,
		},
		{
			name: "nil response",
			args: args{
				ctx: context.Background(),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().ReadWithContext(gomock.Any(), "transit/export/signing-key/test-key/2").Return(nil, nil)
			},
			wantErr: true,
		},
		{
			name: "no keys",
			args: args{
				ctx: context.Background(),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().ReadWithContext(gomock.Any(), "transit/export/signing-key/test-key/2").Return(&api.Secret{
					Data: map[string]interface{}{
						"name": "test-key",
						"keys": map[string]string{},
					},
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "many keys",
			args: args{
				ctx: context.Background(),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().ReadWithContext(gomock.Any(), "transit/export/signing-key/test-key/2").Return(&api.Secret{
					Data: map[string]interface{}{
						"name": "test-key",
						"keys": map[string]string{
							"2": "1zrWO+kyhBceW6nMMaL6GtR425VbkY7AWzEhijq04081g1MnPBPL6yFshJvzpxZFzLNgLGM70yjIZKiFeKuieQ==",
							"3": "BlbgGOvN0vjVvJCaGPotL+HhVFvMtNVSXI/yNouZ6EWPL/eRnUomJ9ZbAkxAew3iPqWIR+hIYj+sgkfYatp6XA==",
						},
					},
				}, nil)
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
			},
			prepare: func(ml *logical.MockLogical) {
				ml.EXPECT().ReadWithContext(gomock.Any(), "transit/export/signing-key/test-key/2").Return(&api.Secret{
					Data: map[string]interface{}{
						"name": "test-key",
						"keys": map[string]string{
							"2": "1zrWO+kyhBceW6nMMaL6GtR425VbkY7AWzEhijq04081g1MnPBPL6yFshJvzpxZFzLNgLGM70yjIZKiFeKuieQ==",
						},
					},
				}, nil)
			},
			wantRaw: "1zrWO+kyhBceW6nMMaL6GtR425VbkY7AWzEhijq04081g1MnPBPL6yFshJvzpxZFzLNgLGM70yjIZKiFeKuieQ==",
			wantKty: kms.KeyTypeEd25519,
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
				canExport:   true,
				lastVersion: 2,
				keyType:     kms.KeyTypeEd25519,
				publicKeys:  map[int]crypto.PublicKey{},
			}

			gotKty, gotRaw, err := underTest.ExportKey(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.ExportKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotRaw, tt.wantRaw) {
				t.Errorf("service.Sign() = %s, wantRaw %s", gotRaw, tt.wantRaw)
			}
			if !reflect.DeepEqual(gotKty, tt.wantKty) {
				t.Errorf("service.Sign() = %d, wantKty %d", gotKty, tt.wantKty)
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
	t.Cleanup(server.Close)

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
			fmt.Fprintln(w, `{"request_id":"07021319-efe6-7585-67d4-38714a7d7546","lease_id":"","renewable":false,"lease_duration":0,"data":{"allow_plaintext_backup":false,"auto_rotate_period":0,"deletion_allowed":false,"derived":false,"exportable":true,"imported_key":false,"keys":{"1":1697801029,"2":1697801283},"latest_version":2,"min_available_version":0,"min_decryption_version":1,"min_encryption_version":0,"name":"symmetric-key","supports_decryption":true,"supports_derivation":true,"supports_encryption":true,"supports_signing":false,"type":"aes256-gcm96"},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/encrypt/symmetric-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"2c420c1f-b840-0339-3ed2-d7a13c9aac5f","lease_id":"","renewable":false,"lease_duration":0,"data":{"ciphertext":"vault:v2:wyrSKtVcDVx9HkAZ76mS+Gtv3Nh2Jmgyw5Xg0k669N8=","key_version":2},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/decrypt/symmetric-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"1941f278-8d6c-89f8-5311-17461db8a8e5","lease_id":"","renewable":false,"lease_duration":0,"data":{"plaintext":"dGVzdA=="},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/export/encryption-key/symmetric-key/2":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"52efa6b4-e080-01e2-d700-e3cd6eeb4877","lease_id":"","renewable":false,"lease_duration":0,"data":{"keys":{"2":"BeHtKOL3iamMVuH19lIcrCKsDvqtDWeyYUhgLDz0c+g="},"name":"symmetric-key","type":"aes256-gcm96"},"wrap_info":null,"warnings":null,"auth":null}`)
		default:
			w.WriteHeader(400)
		}
	}))
	t.Cleanup(server.Close)

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
		assert.Equal(t, []byte("wyrSKtVcDVx9HkAZ76mS+Gtv3Nh2Jmgyw5Xg0k669N8="), got)
	})

	t.Run("Decrypt", func(t *testing.T) {
		got, err := underTest.Decrypt(context.Background(), []byte("wyrSKtVcDVx9HkAZ76mS+Gtv3Nh2Jmgyw5Xg0k669N8="))
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

	t.Run("Export", func(t *testing.T) {
		kty, raw, err := underTest.ExportKey(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, "BeHtKOL3iamMVuH19lIcrCKsDvqtDWeyYUhgLDz0c+g=", raw)
		assert.Equal(t, kms.KeyTypeSymmetric, kty)
	})
}

//nolint:paralleltest // bad behaviour with httptest
func TestService_RSAKey(t *testing.T) {
	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/transit/keys/rsa-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"eb268c78-df3e-b029-7c0a-b1df88c7bdc7","lease_id":"","renewable":false,"lease_duration":0,"data":{"allow_plaintext_backup":false,"auto_rotate_period":0,"deletion_allowed":false,"derived":false,"exportable":true,"imported_key":false,"keys":{"1":{"creation_time":"2023-10-20T13:21:22.619961+02:00","name":"rsa-2048","public_key":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0/YV9CF97gtYfR9k4umE\nVDDWN3/6PzS0UVnX7Ulx3fxpx4vmog6Bl4wKXrXhIx2uEmEUzf2MoVw/iSdfyABi\nL4zY1ftsAx91gBs5FPRd+c+oRh05Xp4mSTNGV3TLRC7R6+GMH1xuiDmLkxwBPCCB\n+lvFJXvKZEM3XcyvEif7k02L4T8LTlyZBu/uNEJyhq7dUw0iCkaJ5PR7iMh6XeyU\nR+qZOheH8w3EFWT9yxJPr8Fbikd/J5ruzmDmQ0xsUKi3qp35T18C9n4aYpOZX8Jg\nNOVGCGT6CTRj7PGRB3EVsPN55S8TM+7OxG1KQ5SF/nx/OTG7abiunwxzH0ZdL7uI\nQwIDAQAB\n-----END PUBLIC KEY-----\n"},"2":{"creation_time":"2023-10-20T13:33:48.976341+02:00","name":"rsa-2048","public_key":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wJdrjQPCnk8dz0I7fyE\nk/F69J5POuzMBRs1RsPauO5jNniZqnCOYJQqlYzHqmZKN2nI+Rh7BlXp3lNRpM1/\nXDlMhiONCSEzqeJfBANd/fHrBnpf7NG/onvpoO8B354rCEW7AJUlqafRzd1qYvLw\nolpPIWZgu6BW6mbeLt6rI+1IX51VNkFCaXg1hy36dgv2+23Sd5iqbRk71dY1VThX\n9JUmEYpf1ZwthpbxsbmaHqHw+jLu3yJYG5Mm42M/q2nOCfoeInmv3nwlMrol6/gB\nI3nh/sFlJJl1uxXa2z2kcDKV8Vr0eb94lwxZYTHzQGQShrqYnSGKFYwLqIDbo8Wu\npwIDAQAB\n-----END PUBLIC KEY-----\n"}},"latest_version":2,"min_available_version":0,"min_decryption_version":1,"min_encryption_version":0,"name":"rsa-key","supports_decryption":true,"supports_derivation":false,"supports_encryption":true,"supports_signing":true,"type":"rsa-2048"},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/encrypt/rsa-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"4986e0e4-6826-8d9f-100f-ea18e13b6810","lease_id":"","renewable":false,"lease_duration":0,"data":{"ciphertext":"vault:v2:iIBgimcTlgWNCAyK0dYB6AwjwnMR2kgneLlcvO9lWB5Btn3KgKVRMKh175R5KCUVEnkhJwBSOUlF6KcOsFXYJi8kmbhYr8ti4bVzp5Tsz42he1XFIxbuHL7xQcJneDcDdPkQj66NCXwytlaMuCwuUMDfC4BL7NjoYSIgB08ckQxP4snxex31KpJ7U6wBXf1mfZtoi6lQfvA8AVLM48bqbL/uoHUM5ECEKc8lYLb76f/po/hq8mPPmMARSQnU5RRjQj4XxApqk0e7OXgjfBL6RnhychhihbyeuCkIf0ZAsUP0O2iqngR9/sfAyAsBXPpexLhQgFAMHraK0OhxkOurWw==","key_version":2},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/decrypt/rsa-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"bee00e75-e8c5-dc70-f718-42bfa864020f","lease_id":"","renewable":false,"lease_duration":0,"data":{"plaintext":"dGVzdA=="},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/sign/rsa-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"c1c26368-138a-3fa5-5bc7-8c5c3baca8de","lease_id":"","renewable":false,"lease_duration":0,"data":{"key_version":2,"signature":"vault:v2:aU9fzuhLAiS82M1hJzGXBzveHegSW_OkW0kNT74imVHIzc2USYgeLl-zCUtMBqkvLGQqdizElLsAnkdm9zLMT5vBUEuLOQLH01lHLBLxYMo-G_G01sOFyYFTYTq1As2bPHvH4H8lmxV1-wYnIn-X1UTtIX7uD53Rf7ffTcYsn101lU0XUIOhowUHVnQkzsQZheRjlUMTDqSvDj_UIc0iCIFka09MULS1Th8hMq80WNmCaTlzktSA7wkZK1H-RQLNF7iITHUIWjKvrKQptHAw3EDaC11ZYhUQOJItBL32hKgfPU0QmlIagD7mcERZ84o3Q5Rofuu4UzeAeblIfrhDdA"},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/verify/rsa-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"a8aa936f-c8e1-a957-026e-2236d5a9b31e","lease_id":"","renewable":false,"lease_duration":0,"data":{"batch_results":[{"valid":true}]},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/export/signing-key/rsa-key/2":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"dececdcf-3e62-a5c1-efc9-e5496c95c493","lease_id":"","renewable":false,"lease_duration":0,"data":{"keys":{"2":"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0wJdrjQPCnk8dz0I7fyEk/F69J5POuzMBRs1RsPauO5jNniZ\nqnCOYJQqlYzHqmZKN2nI+Rh7BlXp3lNRpM1/XDlMhiONCSEzqeJfBANd/fHrBnpf\n7NG/onvpoO8B354rCEW7AJUlqafRzd1qYvLwolpPIWZgu6BW6mbeLt6rI+1IX51V\nNkFCaXg1hy36dgv2+23Sd5iqbRk71dY1VThX9JUmEYpf1ZwthpbxsbmaHqHw+jLu\n3yJYG5Mm42M/q2nOCfoeInmv3nwlMrol6/gBI3nh/sFlJJl1uxXa2z2kcDKV8Vr0\neb94lwxZYTHzQGQShrqYnSGKFYwLqIDbo8WupwIDAQABAoIBAAEL4PUNMwnlQgSB\nW/r6JpopN2fhJRlwtS5NTT1VmU8Td5B8lp5+wmX+NhvZv9+7dCDEOIfrtCh64pcE\nqMH9duU5L4T2xitGa+AqzDfT4HJy8axtjO46uA2ROb5fkQ3P1fzLg7rkAnTN7T9t\nGqr083aKphvPSymDCQtOiUmINycNcuE0gO6JGqxqbtUUjhDN8jNRy7XPu/m/2XL7\n/mjWayt5javyg2+5gi08hbvepedqvLkQ13DlFrgf2EOn/mo9OsXU9rY3L38Dr+ww\nZ48JIQ+O3324g9rlqIXBtOXgKoJ7+IIRrzCerwf25iTjaxkXoeQYcqMOGEyfNn7C\nlzClJtECgYEA5CYgWVwZG6cl0Hze52pPBiWf3pyeQQf5QA4qH4svHvq0KrPW3LZn\nAhfSif+rspM9j/F46MxqFZ24DsvbCCxkkkONPDc96p7SK4t2lwg23DEIwCmhI4rz\njfJS6ssuvzvPnKvMuK4eFhfHiNf33np3MazZ+MEo+/CxIy3ZhtSpnDkCgYEA7MSb\nmJJy0Udbps1Z/LUVKI1W/NRTlrM+jA8A2Htm8747c30QKFmKUXFeB0nHML+plfbz\n6ex+RkMfUTLl5WSE1In7BsyYKFcmeu6vq7ADPAlWT9ayUD3fE5FxSjBNm2/fb2Tp\nZuD/ZSMp8pMGGqwk0U/DsMraWAQoAn6GSZh9Yd8CgYA31PS5qYYjdEYWvVg3PZbV\nJEP5UE6SD4d5m33HdmIzrJqGkLgWDzUqF/ZX+w9jhhDctvUl01BqtcwjItQZLfP2\nrz1S7Rnj3rYEHf8JeuMiA4XmsMlUT17G7/RGrS5lcheeeZSB5WpLccpMvL1V3pZo\nu6oj6/FBpmdS+pdvHX/cUQKBgBtbC+8w3Hs5l2lKSJ9d/LfWvLoxfgbnZs6f3SUl\n/Nskm5HYXUmMLuMCCi8lYxJK0rk08zGP1XcgwjmLe+xpFL/JwWsjsGDY0OVbNojL\nqVQCcCqBT9DdlSyZnVFJC25uGo6wRhdQ37E7wtj4C7iBMy/L23xNs7R/pm/DVpii\nObpZAoGBAIXUWoCVZbzor9HVL2cqubKtzrkbk82bTjQI4jj9iiTy3MXNWboqtx2O\nFCufBOtpcmsJXEjmOBW4z6c1R2kHsa3uuG4wNH+TrJvtIcUj17lMZz9chiHx+/4Y\nJnI/P+v9eYvDz8Xqwuix+LO0IE34umjeFd0wyYNVdY2BRKeNNWtN\n-----END RSA PRIVATE KEY-----\n"},"name":"rsa-key","type":"rsa-2048"},"wrap_info":null,"warnings":null,"auth":null}`)
		default:
			w.WriteHeader(400)
		}
	}))
	t.Cleanup(server.Close)

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
		assert.Equal(t, []byte("iIBgimcTlgWNCAyK0dYB6AwjwnMR2kgneLlcvO9lWB5Btn3KgKVRMKh175R5KCUVEnkhJwBSOUlF6KcOsFXYJi8kmbhYr8ti4bVzp5Tsz42he1XFIxbuHL7xQcJneDcDdPkQj66NCXwytlaMuCwuUMDfC4BL7NjoYSIgB08ckQxP4snxex31KpJ7U6wBXf1mfZtoi6lQfvA8AVLM48bqbL/uoHUM5ECEKc8lYLb76f/po/hq8mPPmMARSQnU5RRjQj4XxApqk0e7OXgjfBL6RnhychhihbyeuCkIf0ZAsUP0O2iqngR9/sfAyAsBXPpexLhQgFAMHraK0OhxkOurWw=="), got)
	})

	t.Run("Decrypt", func(t *testing.T) {
		got, err := underTest.Decrypt(context.Background(), []byte("iIBgimcTlgWNCAyK0dYB6AwjwnMR2kgneLlcvO9lWB5Btn3KgKVRMKh175R5KCUVEnkhJwBSOUlF6KcOsFXYJi8kmbhYr8ti4bVzp5Tsz42he1XFIxbuHL7xQcJneDcDdPkQj66NCXwytlaMuCwuUMDfC4BL7NjoYSIgB08ckQxP4snxex31KpJ7U6wBXf1mfZtoi6lQfvA8AVLM48bqbL/uoHUM5ECEKc8lYLb76f/po/hq8mPPmMARSQnU5RRjQj4XxApqk0e7OXgjfBL6RnhychhihbyeuCkIf0ZAsUP0O2iqngR9/sfAyAsBXPpexLhQgFAMHraK0OhxkOurWw=="))
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
		assert.Equal(t, []byte("aU9fzuhLAiS82M1hJzGXBzveHegSW_OkW0kNT74imVHIzc2USYgeLl-zCUtMBqkvLGQqdizElLsAnkdm9zLMT5vBUEuLOQLH01lHLBLxYMo-G_G01sOFyYFTYTq1As2bPHvH4H8lmxV1-wYnIn-X1UTtIX7uD53Rf7ffTcYsn101lU0XUIOhowUHVnQkzsQZheRjlUMTDqSvDj_UIc0iCIFka09MULS1Th8hMq80WNmCaTlzktSA7wkZK1H-RQLNF7iITHUIWjKvrKQptHAw3EDaC11ZYhUQOJItBL32hKgfPU0QmlIagD7mcERZ84o3Q5Rofuu4UzeAeblIfrhDdA"), got)
	})

	t.Run("Verify", func(t *testing.T) {
		err := underTest.Verify(context.Background(), []byte("protected"), []byte("aU9fzuhLAiS82M1hJzGXBzveHegSW_OkW0kNT74imVHIzc2USYgeLl-zCUtMBqkvLGQqdizElLsAnkdm9zLMT5vBUEuLOQLH01lHLBLxYMo-G_G01sOFyYFTYTq1As2bPHvH4H8lmxV1-wYnIn-X1UTtIX7uD53Rf7ffTcYsn101lU0XUIOhowUHVnQkzsQZheRjlUMTDqSvDj_UIc0iCIFka09MULS1Th8hMq80WNmCaTlzktSA7wkZK1H-RQLNF7iITHUIWjKvrKQptHAw3EDaC11ZYhUQOJItBL32hKgfPU0QmlIagD7mcERZ84o3Q5Rofuu4UzeAeblIfrhDdA"))
		assert.NoError(t, err)
	})

	t.Run("Export", func(t *testing.T) {
		kty, raw, err := underTest.ExportKey(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0wJdrjQPCnk8dz0I7fyEk/F69J5POuzMBRs1RsPauO5jNniZ\nqnCOYJQqlYzHqmZKN2nI+Rh7BlXp3lNRpM1/XDlMhiONCSEzqeJfBANd/fHrBnpf\n7NG/onvpoO8B354rCEW7AJUlqafRzd1qYvLwolpPIWZgu6BW6mbeLt6rI+1IX51V\nNkFCaXg1hy36dgv2+23Sd5iqbRk71dY1VThX9JUmEYpf1ZwthpbxsbmaHqHw+jLu\n3yJYG5Mm42M/q2nOCfoeInmv3nwlMrol6/gBI3nh/sFlJJl1uxXa2z2kcDKV8Vr0\neb94lwxZYTHzQGQShrqYnSGKFYwLqIDbo8WupwIDAQABAoIBAAEL4PUNMwnlQgSB\nW/r6JpopN2fhJRlwtS5NTT1VmU8Td5B8lp5+wmX+NhvZv9+7dCDEOIfrtCh64pcE\nqMH9duU5L4T2xitGa+AqzDfT4HJy8axtjO46uA2ROb5fkQ3P1fzLg7rkAnTN7T9t\nGqr083aKphvPSymDCQtOiUmINycNcuE0gO6JGqxqbtUUjhDN8jNRy7XPu/m/2XL7\n/mjWayt5javyg2+5gi08hbvepedqvLkQ13DlFrgf2EOn/mo9OsXU9rY3L38Dr+ww\nZ48JIQ+O3324g9rlqIXBtOXgKoJ7+IIRrzCerwf25iTjaxkXoeQYcqMOGEyfNn7C\nlzClJtECgYEA5CYgWVwZG6cl0Hze52pPBiWf3pyeQQf5QA4qH4svHvq0KrPW3LZn\nAhfSif+rspM9j/F46MxqFZ24DsvbCCxkkkONPDc96p7SK4t2lwg23DEIwCmhI4rz\njfJS6ssuvzvPnKvMuK4eFhfHiNf33np3MazZ+MEo+/CxIy3ZhtSpnDkCgYEA7MSb\nmJJy0Udbps1Z/LUVKI1W/NRTlrM+jA8A2Htm8747c30QKFmKUXFeB0nHML+plfbz\n6ex+RkMfUTLl5WSE1In7BsyYKFcmeu6vq7ADPAlWT9ayUD3fE5FxSjBNm2/fb2Tp\nZuD/ZSMp8pMGGqwk0U/DsMraWAQoAn6GSZh9Yd8CgYA31PS5qYYjdEYWvVg3PZbV\nJEP5UE6SD4d5m33HdmIzrJqGkLgWDzUqF/ZX+w9jhhDctvUl01BqtcwjItQZLfP2\nrz1S7Rnj3rYEHf8JeuMiA4XmsMlUT17G7/RGrS5lcheeeZSB5WpLccpMvL1V3pZo\nu6oj6/FBpmdS+pdvHX/cUQKBgBtbC+8w3Hs5l2lKSJ9d/LfWvLoxfgbnZs6f3SUl\n/Nskm5HYXUmMLuMCCi8lYxJK0rk08zGP1XcgwjmLe+xpFL/JwWsjsGDY0OVbNojL\nqVQCcCqBT9DdlSyZnVFJC25uGo6wRhdQ37E7wtj4C7iBMy/L23xNs7R/pm/DVpii\nObpZAoGBAIXUWoCVZbzor9HVL2cqubKtzrkbk82bTjQI4jj9iiTy3MXNWboqtx2O\nFCufBOtpcmsJXEjmOBW4z6c1R2kHsa3uuG4wNH+TrJvtIcUj17lMZz9chiHx+/4Y\nJnI/P+v9eYvDz8Xqwuix+LO0IE34umjeFd0wyYNVdY2BRKeNNWtN\n-----END RSA PRIVATE KEY-----\n", raw)
		assert.Equal(t, kms.KeyTypeRSA, kty)
	})
}

//nolint:paralleltest // bad behaviour with httptest
func TestService_ECKey(t *testing.T) {
	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/transit/keys/ec-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"e5fcfb72-5d4a-3b94-e37b-c2e3c0d0a45e","lease_id":"","renewable":false,"lease_duration":0,"data":{"allow_plaintext_backup":false,"auto_rotate_period":0,"deletion_allowed":false,"derived":false,"exportable":true,"imported_key":false,"keys":{"1":{"creation_time":"2023-10-20T13:22:33.999499+02:00","name":"P-256","public_key":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr2/XmGPPP/40nQtySnUSIs8ysae2\nQc9xDKNh+VHWVfXulxzkXUuZbRAnQ85a6Ftbxa/KxxmUng2/tTsHC94yng==\n-----END PUBLIC KEY-----\n"},"2":{"creation_time":"2023-10-20T13:33:53.31413+02:00","name":"P-256","public_key":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH/+38fHS4p4Hd6CF9lfqLFGGLuqo\nFXG0fJ+qNcJMnbmDeaqAfVOr+TAgdNQZyVMkBgM9p+/QgdgmxQTDljWDhg==\n-----END PUBLIC KEY-----\n"}},"latest_version":2,"min_available_version":0,"min_decryption_version":1,"min_encryption_version":0,"name":"ec-key","supports_decryption":false,"supports_derivation":false,"supports_encryption":false,"supports_signing":true,"type":"ecdsa-p256"},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/sign/ec-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"6eb9f857-43fe-2e6c-075f-85faf64ded10","lease_id":"","renewable":false,"lease_duration":0,"data":{"key_version":2,"signature":"vault:v2:wBga6S2Fv-19Vz8Pe2laFwrTAXtZbPKUUdApHhMo9i3DB3dVtAGtYMidBOML02amPeQnuYijBtCip_SOHNXNDw"},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/verify/ec-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"44457b9a-6fd1-d756-1d0a-fe4c102d13d9","lease_id":"","renewable":false,"lease_duration":0,"data":{"batch_results":[{"valid":true}]},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/export/signing-key/ec-key/2":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"b8d50fec-2ac0-4fd2-0a2f-a3eab7b86048","lease_id":"","renewable":false,"lease_duration":0,"data":{"keys":{"2":"-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEILsNXyhB5SqyrvpjWXlDOquqGdJx49dNDCI+XatO3CYroAoGCCqGSM49\nAwEHoUQDQgAEH/+38fHS4p4Hd6CF9lfqLFGGLuqoFXG0fJ+qNcJMnbmDeaqAfVOr\n+TAgdNQZyVMkBgM9p+/QgdgmxQTDljWDhg==\n-----END EC PRIVATE KEY-----"},"name":"ec-key","type":"ecdsa-p256"},"wrap_info":null,"warnings":null,"auth":null}`)
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
		assert.Equal(t, []byte("wBga6S2Fv-19Vz8Pe2laFwrTAXtZbPKUUdApHhMo9i3DB3dVtAGtYMidBOML02amPeQnuYijBtCip_SOHNXNDw"), got)
	})

	t.Run("Verify", func(t *testing.T) {
		err := underTest.Verify(context.Background(), []byte("protected"), []byte("wBga6S2Fv-19Vz8Pe2laFwrTAXtZbPKUUdApHhMo9i3DB3dVtAGtYMidBOML02amPeQnuYijBtCip_SOHNXNDw"))
		assert.NoError(t, err)
	})

	t.Run("Export", func(t *testing.T) {
		kty, raw, err := underTest.ExportKey(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEILsNXyhB5SqyrvpjWXlDOquqGdJx49dNDCI+XatO3CYroAoGCCqGSM49\nAwEHoUQDQgAEH/+38fHS4p4Hd6CF9lfqLFGGLuqoFXG0fJ+qNcJMnbmDeaqAfVOr\n+TAgdNQZyVMkBgM9p+/QgdgmxQTDljWDhg==\n-----END EC PRIVATE KEY-----", raw)
		assert.Equal(t, kms.KeyTypeECDSA, kty)
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
			fmt.Fprintln(w, `{"request_id":"1dccb175-9dfb-86ce-9748-d56ecd859c9e","lease_id":"","renewable":false,"lease_duration":0,"data":{"allow_plaintext_backup":false,"auto_rotate_period":0,"deletion_allowed":false,"derived":false,"exportable":true,"imported_key":false,"keys":{"1":{"creation_time":"2023-10-20T13:22:55.218283+02:00","name":"ed25519","public_key":"rWNIKBkLV1FC4+68s1jOLFHq+oC7yisn3HIQQcTk5Bg="},"2":{"creation_time":"2023-10-20T13:34:01.09267+02:00","name":"ed25519","public_key":"NYNTJzwTy+shbISb86cWRcyzYCxjO9MoyGSohXironk="}},"latest_version":2,"min_available_version":0,"min_decryption_version":1,"min_encryption_version":0,"name":"ed25519-key","supports_decryption":false,"supports_derivation":true,"supports_encryption":false,"supports_signing":true,"type":"ed25519"},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/sign/ed25519-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"07e46c05-4d80-4657-0eac-023d4e3cf61f","lease_id":"","renewable":false,"lease_duration":0,"data":{"key_version":2,"signature":"vault:v2:5qLfzfo9jbah-zSXODGL2bxESjZJj0lsLpsDk7BJyL-A7yvB6pSD5BNr6ij1yO80L8P1iMr8m-4SNOZvYpheAg"},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/verify/ed25519-key":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"2ded8d72-088c-9258-3999-05a00f8f1144","lease_id":"","renewable":false,"lease_duration":0,"data":{"batch_results":[{"valid":true}]},"wrap_info":null,"warnings":null,"auth":null}`)
		case "/v1/transit/export/signing-key/ed25519-key/2":
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"request_id":"b3e2023e-2c44-3828-1079-c6b1faa840bf","lease_id":"","renewable":false,"lease_duration":0,"data":{"keys":{"2":"1zrWO+kyhBceW6nMMaL6GtR425VbkY7AWzEhijq04081g1MnPBPL6yFshJvzpxZFzLNgLGM70yjIZKiFeKuieQ=="},"name":"ed25519-key","type":"ed25519"},"wrap_info":null,"warnings":null,"auth":null}`)
		default:
			w.WriteHeader(400)
		}
	}))
	t.Cleanup(server.Close)

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
		assert.Equal(t, []byte("5qLfzfo9jbah-zSXODGL2bxESjZJj0lsLpsDk7BJyL-A7yvB6pSD5BNr6ij1yO80L8P1iMr8m-4SNOZvYpheAg"), got)
	})

	t.Run("Verify", func(t *testing.T) {
		err := underTest.Verify(context.Background(), []byte("protected"), []byte("5qLfzfo9jbah-zSXODGL2bxESjZJj0lsLpsDk7BJyL-A7yvB6pSD5BNr6ij1yO80L8P1iMr8m-4SNOZvYpheAg"))
		assert.NoError(t, err)
	})

	t.Run("Export", func(t *testing.T) {
		kty, raw, err := underTest.ExportKey(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, "1zrWO+kyhBceW6nMMaL6GtR425VbkY7AWzEhijq04081g1MnPBPL6yFshJvzpxZFzLNgLGM70yjIZKiFeKuieQ==", raw)
		assert.Equal(t, kms.KeyTypeEd25519, kty)
	})
}
