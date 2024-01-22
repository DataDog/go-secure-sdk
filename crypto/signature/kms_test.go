package signature

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	security "github.com/DataDog/go-secure-sdk"
	"github.com/DataDog/go-secure-sdk/crypto/keyutil/deterministicecdsa"
	kmsmock "github.com/DataDog/go-secure-sdk/kms/mock"
)

func TestRemoteSignerNil(t *testing.T) {
	t.Parallel()

	s, err := RemoteSigner(context.TODO(), nil)
	if err == nil {
		t.Fatal("error must be raised with a nil service")
	}
	if s != nil {
		t.Fatal("signer must be nil")
	}
}

func TestRemoteSigner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*kmsmock.MockService)
		wantErr bool
	}{
		{
			name: "key retrieval error",
			prepare: func(ms *kmsmock.MockService) {
				ms.EXPECT().PublicKey(gomock.Any()).Return(nil, errors.New("test"))
			},
			wantErr: true,
		},
		{
			name: "key serialization error",
			prepare: func(ms *kmsmock.MockService) {
				ms.EXPECT().PublicKey(gomock.Any()).Return(&struct{}{}, nil)
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid - ed25519",
			prepare: func(ms *kmsmock.MockService) {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				ms.EXPECT().PublicKey(gomock.Any()).Return(pub, nil)
			},
			wantErr: false,
		},
		{
			name: "valid - ecdsa-p256",
			prepare: func(ms *kmsmock.MockService) {
				pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				ms.EXPECT().PublicKey(gomock.Any()).Return(pk.Public(), nil)
			},
			wantErr: false,
		},
		{
			name: "valid - ecdsa-p384",
			prepare: func(ms *kmsmock.MockService) {
				pk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				ms.EXPECT().PublicKey(gomock.Any()).Return(pk.Public(), nil)
			},
			wantErr: false,
		},
		{
			name: "valid - ecdsa-p521",
			prepare: func(ms *kmsmock.MockService) {
				pk, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				ms.EXPECT().PublicKey(gomock.Any()).Return(pk.Public(), nil)
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

			mockTransit := kmsmock.NewMockService(ctrl)
			if tt.prepare != nil {
				tt.prepare(mockTransit)
			}

			_, err := RemoteSigner(context.Background(), mockTransit)
			if (err != nil) != tt.wantErr {
				t.Errorf("VaultTransitSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_RemoteSigner_Algorithm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*kmsmock.MockService)
		want    Algorithm
	}{
		{
			name: "valid - ed25519",
			prepare: func(ms *kmsmock.MockService) {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				ms.EXPECT().PublicKey(gomock.Any()).Return(pub, nil)
			},
			want: Ed25519Signature,
		},
		{
			name: "valid - ecdsa-p256",
			prepare: func(ms *kmsmock.MockService) {
				pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				ms.EXPECT().PublicKey(gomock.Any()).Return(pk.Public(), nil)
			},
			want: ECDSAP256Signature,
		},
		{
			name: "valid - ecdsa-p384",
			prepare: func(ms *kmsmock.MockService) {
				pk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				ms.EXPECT().PublicKey(gomock.Any()).Return(pk.Public(), nil)
			},
			want: ECDSAP384Signature,
		},
		{
			name: "valid - ecdsa-p521",
			prepare: func(ms *kmsmock.MockService) {
				pk, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				ms.EXPECT().PublicKey(gomock.Any()).Return(pk.Public(), nil)
			},
			want: ECDSAP521Signature,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockTransit := kmsmock.NewMockService(ctrl)
			if tt.prepare != nil {
				tt.prepare(mockTransit)
			}

			s, err := RemoteSigner(context.TODO(), mockTransit)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.Algorithm(); got != tt.want {
				t.Errorf("kmsSigner.Algorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_RemoteSigner_Sign(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*kmsmock.MockService)
		want    []byte
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
			want:    []byte("fake-signature"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockTransit := kmsmock.NewMockService(ctrl)
			if tt.prepare != nil {
				tt.prepare(mockTransit)
			}

			s := &kmsSigner{
				ctx:    context.TODO(),
				dopts:  &kmsOptions{},
				remote: mockTransit,
			}
			got, err := s.Sign([]byte{})
			if (err != nil) != tt.wantErr {
				t.Errorf("kmsSigner.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("kmsSigner.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_RemoteSigner_PublicKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*kmsmock.MockService)
		want    []byte
	}{
		{
			name: "valid - ed25519",
			prepare: func(ms *kmsmock.MockService) {
				pub, _, _ := ed25519.GenerateKey(strings.NewReader("0000-deterministic-seed-for-testing-purpose"))
				ms.EXPECT().PublicKey(gomock.Any()).Return(pub, nil)
			},
			want: mustHexDecode("24ae142032a901b6345115496529ed6dd25f912eab9856a7212ecd96ec2709fe"),
		},
		{
			name: "valid - ecdsa-p256",
			prepare: func(ms *kmsmock.MockService) {
				pk, _ := deterministicecdsa.GenerateKey(elliptic.P256(), strings.NewReader("0000-deterministic-seed-for-testing-purpose"))
				ms.EXPECT().PublicKey(gomock.Any()).Return(pk.Public(), nil)
			},
			want: mustHexDecode("02a0909a828600d074d60ceb69d79c6d19fd469ff01dff088661170515d016d488"),
		},
		{
			name: "valid - ecdsa-p384",
			prepare: func(ms *kmsmock.MockService) {
				pk, _ := deterministicecdsa.GenerateKey(elliptic.P384(), strings.NewReader("0000-deterministic-seed-for-testing-purpose-12345678901234567890"))
				ms.EXPECT().PublicKey(gomock.Any()).Return(pk.Public(), nil)
			},
			want: mustHexDecode("023aede642a238c8e45beb89cbaff47ed00443fbeae8136c59800287cb738f44c51b45b4921005bfc604fb5e4b90f96c44"),
		},
		{
			name: "valid - ecdsa-p521",
			prepare: func(ms *kmsmock.MockService) {
				pk, _ := deterministicecdsa.GenerateKey(elliptic.P521(), strings.NewReader("0000-deterministic-seed-for-testing-purpose-123456789012345678901234567890123456789012345678901234567890"))
				ms.EXPECT().PublicKey(gomock.Any()).Return(pk.Public(), nil)
			},
			want: mustHexDecode("02012838944abceb999417a0289e0fbf6032a2361d6569a82acffe7214ec0f8abdf426a028b1be53f39d726a22cffb4c7c03a8bbbadb39259a18eb9acc64e3415d1be5"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockTransit := kmsmock.NewMockService(ctrl)
			if tt.prepare != nil {
				tt.prepare(mockTransit)
			}

			s, err := RemoteSigner(context.TODO(), mockTransit)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.PublicKey(); !bytes.Equal(got, tt.want) {
				t.Errorf("vaultTransitSigner.PublicKey() = %x, want %x", got, tt.want)
			}
		})
	}
}

//nolint:paralleltest // Disable parallel testing due to the stateful nature of the FIPS flag
func TestRemoteSigner_FIPSMode(t *testing.T) {
	revertFunc := security.SetFIPSMode()
	require.True(t, security.InFIPSMode())
	defer revertFunc()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTransit := kmsmock.NewMockService(ctrl)
	pub, _, _ := ed25519.GenerateKey(strings.NewReader("0000-deterministic-seed-for-testing-purpose"))
	mockTransit.EXPECT().PublicKey(gomock.Any()).Return(pub, nil)

	s, err := RemoteSigner(context.TODO(), mockTransit)
	require.Error(t, err)
	require.Nil(t, s)
}

func TestRemoteVerifierNil(t *testing.T) {
	t.Parallel()

	s, err := RemoteVerifier(context.Background(), nil)
	if err == nil {
		t.Fatal("error must be raised with a nil service")
	}
	if s != nil {
		t.Fatal("verifier must be nil")
	}
}

func TestRemoteVerifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*kmsmock.MockService)
		wantErr bool
	}{
		{
			name: "key retrieval error",
			prepare: func(ms *kmsmock.MockService) {
				ms.EXPECT().PublicKey(gomock.Any()).Return(nil, errors.New("test"))
			},
			wantErr: true,
		},
		{
			name: "key serialization error",
			prepare: func(ms *kmsmock.MockService) {
				ms.EXPECT().PublicKey(gomock.Any()).Return(&struct{}{}, nil)
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid - ed25519",
			prepare: func(ms *kmsmock.MockService) {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				ms.EXPECT().PublicKey(gomock.Any()).Return(pub, nil)
			},
			wantErr: false,
		},
		{
			name: "valid - ecdsa-p256",
			prepare: func(ms *kmsmock.MockService) {
				pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				ms.EXPECT().PublicKey(gomock.Any()).Return(pk.Public(), nil)
			},
			wantErr: false,
		},
		{
			name: "valid - ecdsa-p384",
			prepare: func(ms *kmsmock.MockService) {
				pk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				ms.EXPECT().PublicKey(gomock.Any()).Return(pk.Public(), nil)
			},
			wantErr: false,
		},
		{
			name: "valid - ecdsa-p521",
			prepare: func(ms *kmsmock.MockService) {
				pk, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				ms.EXPECT().PublicKey(gomock.Any()).Return(pk.Public(), nil)
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

			mockTransit := kmsmock.NewMockService(ctrl)
			if tt.prepare != nil {
				tt.prepare(mockTransit)
			}

			_, err := RemoteVerifier(context.Background(), mockTransit)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoteVerifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func mustHexDecode(in string) []byte {
	out, err := hex.DecodeString(in)
	if err != nil {
		panic(err)
	}
	return out
}
