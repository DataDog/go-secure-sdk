// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"

	"github.com/DataDog/go-secure-sdk/crypto/signature"
	v1 "github.com/DataDog/go-secure-sdk/crypto/signature/envelope/internal/v1"
	"github.com/DataDog/go-secure-sdk/crypto/signature/test/mock"
	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

func TestWrapAndSign(t *testing.T) {
	t.Parallel()

	type args struct {
		contentType string
		payload     []byte
		opts        []Option
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*mock.MockSigner)
		want    *Envelope
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "blank content type",
			args: args{
				contentType: "",
			},
			wantErr: true,
		},
		{
			name: "empty public key",
			args: args{
				contentType: "types.datadoghq.com/workflow/v1/RunAction",
			},
			prepare: func(ms *mock.MockSigner) {
				ms.EXPECT().PublicKey().Return([]byte{})
			},
			wantErr: true,
		},
		{
			name: "sign error",
			args: args{
				contentType: "types.datadoghq.com/workflow/v1/RunAction",
			},
			prepare: func(ms *mock.MockSigner) {
				ms.EXPECT().PublicKey().Return([]byte("fake-public-key"))
				ms.EXPECT().Algorithm().Return(signature.Algorithm("mock-signer"))
				ms.EXPECT().Sign(gomock.Any()).Return(nil, errors.New("test"))
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				contentType: "types.datadoghq.com/workflow/v1/RunAction",
				payload:     []byte("hello world"),
				opts: []Option{
					WithTimestamp(1),
				},
			},
			prepare: func(ms *mock.MockSigner) {
				ms.EXPECT().PublicKey().Return([]byte("fake-public-key"))
				ms.EXPECT().Algorithm().Return(signature.Algorithm("mock-signer"))
				ms.EXPECT().Sign(gomock.Any()).Return([]byte("fake-signature"), nil)
			},
			wantErr: false,
			want: &Envelope{
				ContentType: "types.datadoghq.com/workflow/v1/RunAction",
				Content:     []byte("hello world"),
				Signature: &Signature{
					Version:   SigningVersion,
					Algorithm: "mock-signer",
					PublicKeyID: []byte{
						0xbe, 0x3e, 0x68, 0x45, 0x58, 0x59, 0x9a, 0x50,
						0xeb, 0x13, 0x81, 0xb8, 0x44, 0xa3, 0x55, 0xdf,
						0xb1, 0x2d, 0x82, 0xbf, 0xd7, 0xb8, 0xd3, 0xb0,
						0x10, 0x50, 0x33, 0x6f, 0xcf, 0x3c, 0xfc, 0xa3,
					},
					Proof:     []byte("fake-signature"),
					Timestamp: 1,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockSigner := mock.NewMockSigner(ctrl)
			if tt.prepare != nil {
				tt.prepare(mockSigner)
			}

			got, err := WrapAndSign(tt.args.contentType, tt.args.payload, mockSigner, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("WrapAndSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if report := cmp.Diff(got, tt.want); report != "" {
				t.Errorf("WrapAndSign() = \n%s", report)
			}
		})
	}
}

func TestVerifyAndUnwrap(t *testing.T) {
	t.Parallel()

	type args struct {
		e *Envelope
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*mock.MockVerifier)
		want    []byte
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "nil envelope",
			args: args{
				e: nil,
			},
			wantErr: true,
		},
		{
			name: "nil signature",
			args: args{
				e: &Envelope{},
			},
			wantErr: true,
		},
		{
			name: "unsupported version",
			args: args{
				e: &Envelope{
					ContentType: "types.datadoghq.com/workflow/v1/RunAction",
					Content:     []byte("hello world"),
					Signature: &Signature{
						Version:   0,
						Algorithm: "mock-signer",
						PublicKeyID: []byte{
							0xbe, 0x3e, 0x68, 0x45, 0x58, 0x59, 0x9a, 0x50,
							0xeb, 0x13, 0x81, 0xb8, 0x44, 0xa3, 0x55, 0xdf,
							0xb1, 0x2d, 0x82, 0xbf, 0xd7, 0xb8, 0xd3, 0xb0,
							0x10, 0x50, 0x33, 0x6f, 0xcf, 0x3c, 0xfc, 0xa3,
						},
						Proof: []byte("fake-signature"),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "algorithm mismatch",
			args: args{
				e: &Envelope{
					ContentType: "types.datadoghq.com/workflow/v1/RunAction",
					Content:     []byte("hello world"),
					Signature: &Signature{
						Version:   SigningVersion,
						Algorithm: "mock-signer",
						PublicKeyID: []byte{
							0xbe, 0x3e, 0x68, 0x45, 0x58, 0x59, 0x9a, 0x50,
							0xeb, 0x13, 0x81, 0xb8, 0x44, 0xa3, 0x55, 0xdf,
							0xb1, 0x2d, 0x82, 0xbf, 0xd7, 0xb8, 0xd3, 0xb0,
							0x10, 0x50, 0x33, 0x6f, 0xcf, 0x3c, 0xfc, 0xa3,
						},
						Proof: []byte("fake-signature"),
					},
				},
			},
			prepare: func(mv *mock.MockVerifier) {
				mv.EXPECT().Algorithm().Return(signature.Algorithm("other-signer"))
			},
			wantErr: true,
		},
		{
			name: "empty public key",
			args: args{
				e: &Envelope{
					ContentType: "types.datadoghq.com/workflow/v1/RunAction",
					Content:     []byte("hello world"),
					Signature: &Signature{
						Version:   SigningVersion,
						Algorithm: "mock-signer",
						PublicKeyID: []byte{
							0xbe, 0x3e, 0x68, 0x45, 0x58, 0x59, 0x9a, 0x50,
							0xeb, 0x13, 0x81, 0xb8, 0x44, 0xa3, 0x55, 0xdf,
							0xb1, 0x2d, 0x82, 0xbf, 0xd7, 0xb8, 0xd3, 0xb0,
							0x10, 0x50, 0x33, 0x6f, 0xcf, 0x3c, 0xfc, 0xa3,
						},
						Proof: []byte("fake-signature"),
					},
				},
			},
			prepare: func(mv *mock.MockVerifier) {
				mv.EXPECT().Algorithm().Return(signature.Algorithm("mock-signer"))
				mv.EXPECT().PublicKey().Return([]byte{})
			},
			wantErr: true,
		},
		{
			name: "public key mismatch",
			args: args{
				e: &Envelope{
					ContentType: "types.datadoghq.com/workflow/v1/RunAction",
					Content:     []byte("hello world"),
					Signature: &Signature{
						Version:   SigningVersion,
						Algorithm: "mock-signer",
						PublicKeyID: []byte{
							0xbe, 0x3e, 0x68, 0x45, 0x58, 0x59, 0x9a, 0x50,
							0xeb, 0x13, 0x81, 0xb8, 0x44, 0xa3, 0x55, 0xdf,
							0xb1, 0x2d, 0x82, 0xbf, 0xd7, 0xb8, 0xd3, 0xb0,
							0x10, 0x50, 0x33, 0x6f, 0xcf, 0x3c, 0xfc, 0xa3,
						},
						Proof: []byte("fake-signature"),
					},
				},
			},
			prepare: func(mv *mock.MockVerifier) {
				mv.EXPECT().Algorithm().Return(signature.Algorithm("mock-signer"))
				mv.EXPECT().PublicKey().Return([]byte("another-public-key"))
			},
			wantErr: true,
		},
		{
			name: "version not supported",
			args: args{
				e: &Envelope{
					ContentType: "types.datadoghq.com/workflow/v1/RunAction",
					Content:     []byte("hello world"),
					Signature: &Signature{
						Version:   99,
						Algorithm: "mock-signer",
						PublicKeyID: []byte{
							0xbe, 0x3e, 0x68, 0x45, 0x58, 0x59, 0x9a, 0x50,
							0xeb, 0x13, 0x81, 0xb8, 0x44, 0xa3, 0x55, 0xdf,
							0xb1, 0x2d, 0x82, 0xbf, 0xd7, 0xb8, 0xd3, 0xb0,
							0x10, 0x50, 0x33, 0x6f, 0xcf, 0x3c, 0xfc, 0xa3,
						},
						Proof: []byte("fake-signature"),
					},
				},
			},
			prepare: func(mv *mock.MockVerifier) {
				mv.EXPECT().Algorithm().Return(signature.Algorithm("mock-signer"))
				mv.EXPECT().PublicKey().Return([]byte("fake-public-key"))
			},
			wantErr: true,
		},
		{
			name: "verify error",
			args: args{
				e: &Envelope{
					ContentType: "types.datadoghq.com/workflow/v1/RunAction",
					Content:     []byte("hello world"),
					Signature: &Signature{
						Version:   SigningVersion,
						Algorithm: "mock-signer",
						PublicKeyID: []byte{
							0xbe, 0x3e, 0x68, 0x45, 0x58, 0x59, 0x9a, 0x50,
							0xeb, 0x13, 0x81, 0xb8, 0x44, 0xa3, 0x55, 0xdf,
							0xb1, 0x2d, 0x82, 0xbf, 0xd7, 0xb8, 0xd3, 0xb0,
							0x10, 0x50, 0x33, 0x6f, 0xcf, 0x3c, 0xfc, 0xa3,
						},
						Proof: []byte("fake-signature"),
					},
				},
			},
			prepare: func(mv *mock.MockVerifier) {
				mv.EXPECT().Algorithm().Return(signature.Algorithm("mock-signer"))
				mv.EXPECT().PublicKey().Return([]byte("fake-public-key"))
				mv.EXPECT().Verify(gomock.Any(), gomock.Any()).Return(errors.New("test"))
			},
			wantErr: true,
		},
		{
			name: "valid - v1",
			args: args{
				e: &Envelope{
					ContentType: "types.datadoghq.com/workflow/v1/RunAction",
					Content:     []byte("hello world"),
					Signature: &Signature{
						Version:   v1.Version,
						Algorithm: "mock-signer",
						PublicKeyID: []byte{
							0x22, 0x44, 0x8e, 0x62, 0x45, 0xea, 0x6b, 0x80,
							0x3d, 0x44, 0xfa, 0xc4, 0xf3, 0x6f, 0xd1, 0x11,
							0x61, 0x86, 0x13, 0x62, 0x28, 0x39, 0x64, 0xab,
							0xc4, 0x18, 0xbb, 0x50, 0x9a, 0xc2, 0x66, 0xa1,
						},
						Proof: []byte("fake-signature"),
					},
				},
			},
			prepare: func(mv *mock.MockVerifier) {
				mv.EXPECT().Algorithm().Return(signature.Algorithm("mock-signer"))
				mv.EXPECT().PublicKey().Return([]byte("fake-public-key"))
				mv.EXPECT().Verify(gomock.Any(), gomock.Any()).Return(nil)
			},
			wantErr: false,
			want:    []byte("hello world"),
		},
		{
			name: "valid - v2",
			args: args{
				e: &Envelope{
					ContentType: "types.datadoghq.com/workflow/v1/RunAction",
					Content:     []byte("hello world"),
					Signature: &Signature{
						Version:   SigningVersion,
						Algorithm: "mock-signer",
						PublicKeyID: []byte{
							0xbe, 0x3e, 0x68, 0x45, 0x58, 0x59, 0x9a, 0x50,
							0xeb, 0x13, 0x81, 0xb8, 0x44, 0xa3, 0x55, 0xdf,
							0xb1, 0x2d, 0x82, 0xbf, 0xd7, 0xb8, 0xd3, 0xb0,
							0x10, 0x50, 0x33, 0x6f, 0xcf, 0x3c, 0xfc, 0xa3,
						},
						Proof: []byte("fake-signature"),
					},
				},
			},
			prepare: func(mv *mock.MockVerifier) {
				mv.EXPECT().Algorithm().Return(signature.Algorithm("mock-signer"))
				mv.EXPECT().PublicKey().Return([]byte("fake-public-key"))
				mv.EXPECT().Verify(gomock.Any(), gomock.Any()).Return(nil)
			},
			wantErr: false,
			want:    []byte("hello world"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockVerifier := mock.NewMockVerifier(ctrl)
			if tt.prepare != nil {
				tt.prepare(mockVerifier)
			}

			got, err := VerifyAndUnwrap(tt.args.e, mockVerifier)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyAndUnwrap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VerifyAndUnwrap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkWrapAndSignEd25519(b *testing.B) {
	_, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("1", benchmarkWrapAndSign(1, pk))
	b.Run("32", benchmarkWrapAndSign(32, pk))
	b.Run("64", benchmarkWrapAndSign(64, pk))
	b.Run("1k", benchmarkWrapAndSign(1024, pk))
	b.Run("32k", benchmarkWrapAndSign(32*1024, pk))
	b.Run("64k", benchmarkWrapAndSign(64*1024, pk))
}

func BenchmarkWrapAndSignEC(b *testing.B) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}
	for _, c := range curves {
		b.Run(c.Params().Name, func(b *testing.B) {
			pk, err := ecdsa.GenerateKey(c, rand.Reader)
			if err != nil {
				b.Fatal(err)
			}

			b.Run("1", benchmarkWrapAndSign(1, pk))
			b.Run("32", benchmarkWrapAndSign(32, pk))
			b.Run("64", benchmarkWrapAndSign(64, pk))
			b.Run("1k", benchmarkWrapAndSign(1024, pk))
			b.Run("32k", benchmarkWrapAndSign(32*1024, pk))
			b.Run("64k", benchmarkWrapAndSign(64*1024, pk))
		})
	}
}

//nolint:errcheck // Disabled for benchmark
func benchmarkWrapAndSign(inputLen int, pk crypto.Signer) func(*testing.B) {
	return func(b *testing.B) {
		b.ReportAllocs()
		s, err := signature.FromPrivateKey(pk)
		if err != nil {
			b.Fatal(err)
		}

		buf := &bytes.Buffer{}
		io.CopyN(buf, randomness.Reader, int64(inputLen))
		msg := buf.Bytes()

		for i := 0; i < b.N; i++ {
			b.SetBytes(int64(inputLen))
			WrapAndSign("benchmarking", msg, s)
		}
	}
}

func BenchmarkVerifyAndUnwrapEd25519(b *testing.B) {
	pub, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("1", benchmarkVerifyAndUnwrap(1, pk, pub))
	b.Run("32", benchmarkVerifyAndUnwrap(32, pk, pub))
	b.Run("64", benchmarkVerifyAndUnwrap(64, pk, pub))
	b.Run("1k", benchmarkVerifyAndUnwrap(1024, pk, pub))
	b.Run("32k", benchmarkVerifyAndUnwrap(32*1024, pk, pub))
	b.Run("64k", benchmarkVerifyAndUnwrap(64*1024, pk, pub))
}

func BenchmarkVerifyAndUnwrapEC(b *testing.B) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}
	for _, c := range curves {
		b.Run(c.Params().Name, func(b *testing.B) {
			pk, err := ecdsa.GenerateKey(c, rand.Reader)
			if err != nil {
				b.Fatal(err)
			}

			b.Run("1", benchmarkVerifyAndUnwrap(1, pk, pk.Public()))
			b.Run("32", benchmarkVerifyAndUnwrap(32, pk, pk.Public()))
			b.Run("64", benchmarkVerifyAndUnwrap(64, pk, pk.Public()))
			b.Run("1k", benchmarkVerifyAndUnwrap(1024, pk, pk.Public()))
			b.Run("32k", benchmarkVerifyAndUnwrap(32*1024, pk, pk.Public()))
			b.Run("64k", benchmarkVerifyAndUnwrap(64*1024, pk, pk.Public()))
		})
	}
}

//nolint:errcheck // Disabled for benchmark
func benchmarkVerifyAndUnwrap(inputLen int, pk crypto.Signer, pub crypto.PublicKey) func(*testing.B) {
	return func(b *testing.B) {
		b.ReportAllocs()
		v, err := signature.FromPublicKey(pub)
		if err != nil {
			b.Fatal(err)
		}

		s, err := signature.FromPrivateKey(pk)
		if err != nil {
			b.Fatal(err)
		}
		buf := &bytes.Buffer{}
		io.CopyN(buf, randomness.Reader, int64(inputLen))
		msg := buf.Bytes()

		e, err := WrapAndSign("benchmarking", msg, s)
		if err != nil {
			b.Fatal(err)
		}

		for i := 0; i < b.N; i++ {
			b.SetBytes(int64(inputLen))
			VerifyAndUnwrap(e, v)
		}
	}
}
