// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package d3

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

var _ io.Reader = (*fakeReader)(nil)

type fakeReader struct{}

func (fr *fakeReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("error")
}

func Test_encrypt(t *testing.T) {
	t.Parallel()

	type args struct {
		r         io.Reader
		key       []byte
		plaintext io.Reader
		aad       []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "key too short",
			args: args{
				r:   rand.Reader,
				key: []byte{},
			},
			wantErr: true,
		},
		{
			name: "random reader error",
			args: args{
				r:   &fakeReader{},
				key: []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
			},
			wantErr: true,
		},
		{
			name: "plaintext reader error",
			args: args{
				r:         rand.Reader,
				key:       []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
				plaintext: &fakeReader{},
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				r:         randomness.NewReader(1), // Deterministic random source
				key:       []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
				plaintext: strings.NewReader(`{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}`),
			},
			wantErr: false,
			want: []byte{
				0xd3, 0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d,
				0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c, 0x4d, 0x7b, 0xbb, 0x04, 0x07, 0xd1, 0xe2, 0xc6,
				0x49, 0x01, 0x17, 0xf3, 0xe1, 0x92, 0xd5, 0x66, 0xa8, 0x3a, 0x43, 0xba, 0x97, 0x96, 0xdf, 0xf6,
				0xb8, 0x69, 0xc6, 0x84, 0x4d, 0xa1, 0x1e, 0x83, 0xb7, 0xfc, 0xc3, 0x7f, 0xbc, 0x94, 0x4a, 0xc5,
				0x85, 0x41, 0x06, 0xd4, 0xfb, 0x7b, 0x1a, 0x4a, 0x45, 0xe1, 0x8e, 0xbe, 0x29, 0x13, 0x92, 0x02,
				0x69, 0xf1, 0xb7, 0xf0, 0x0e, 0xdc, 0xd9, 0xab, 0x67, 0xc2, 0x07, 0x4d, 0x3e, 0xa2, 0xf8, 0xca,
				0x87, 0x01,
			},
		},
		{
			name: "valid with aad",
			args: args{
				r:         randomness.NewReader(1), // Deterministic random source
				key:       []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
				plaintext: strings.NewReader(`{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}`),
				aad:       []byte(`{"uid":"8f41b712-663f-48a8-b43c-54cf97a94d1a"}`),
			},
			wantErr: false,
			want: []byte{
				0xd3, 0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d,
				0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c, 0x4d, 0x7b, 0xbb, 0x04, 0x07, 0xd1, 0xe2, 0xc6,
				0x49, 0x01, 0x17, 0xf3, 0xe1, 0x92, 0xd5, 0x66, 0xa8, 0x3a, 0x43, 0xba, 0x97, 0x96, 0xdf, 0xf6,
				0xb8, 0x69, 0xc6, 0x84, 0x4d, 0xa1, 0x1e, 0x83, 0xb7, 0xfc, 0xc3, 0x7f, 0xbc, 0x94, 0x4a, 0xc5,
				0x85, 0x41, 0x06, 0xd4, 0xfb, 0x7b, 0x1a, 0x4a, 0x45, 0xe1, 0x8e, 0xbe, 0x29, 0x13, 0x92, 0x02,
				0x69, 0xf1, 0xd3, 0x6e, 0x96, 0xb5, 0x15, 0x75, 0x83, 0x04, 0xb9, 0xc9, 0x2f, 0xac, 0x4d, 0xfb,
				0xed, 0xf2,
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			err := encrypt(tt.args.r, tt.args.key, tt.args.plaintext, tt.args.aad, &out)
			if (err != nil) != tt.wantErr {
				t.Errorf("encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			got := out.Bytes()
			if report := cmp.Diff(tt.want, got); report != "" {
				t.Errorf("encrypt() = \n%s", report)
			}
		})
	}
}

func Test_decrypt(t *testing.T) {
	t.Parallel()

	type args struct {
		key        []byte
		ciphertext io.Reader
		aad        []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "key too short",
			args: args{
				key: []byte(""),
			},
			wantErr: true,
		},
		{
			name: "ciphertext too short",
			args: args{
				key:        []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
				ciphertext: bytes.NewReader([]byte{}),
			},
			wantErr: true,
		},
		{
			name: "invalid version",
			args: args{
				key: []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
				ciphertext: bytes.NewReader([]byte{
					0xFF, 0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d,
					0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c, 0x4d, 0x7b, 0xbb, 0x04, 0x07, 0xd1, 0xe2, 0xc6,
					0x49, 0x01, 0x17, 0xf3, 0xe1, 0x92, 0xd5, 0x66, 0xa8, 0x3a, 0x43, 0xba, 0x97, 0x96, 0xdf, 0xf6,
					0xb8, 0x69, 0xc6, 0x84, 0x4d, 0xa1, 0x1e, 0x83, 0xb7, 0xfc, 0xc3, 0x7f, 0xbc, 0x94, 0x4a, 0xc5,
					0x85, 0x41, 0x06, 0xd4, 0xfb, 0x7b, 0x1a, 0x4a, 0x45, 0xe1, 0x8e, 0xbe, 0x29, 0x13, 0x92, 0x02,
					0x69, 0xf1, 0xb7, 0xf0, 0x0e, 0xdc, 0xd9, 0xab, 0x67, 0xc2, 0x07, 0x4d, 0x3e, 0xa2, 0xf8, 0xca,
					0x87, 0x01,
				}),
			},
			wantErr: true,
		},
		{
			name: "tampered nonce",
			args: args{
				key: []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
				ciphertext: bytes.NewReader([]byte{
					0xd3, 0xFF, 0xFF, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d,
					0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c, 0x4d, 0x7b, 0xbb, 0x04, 0x07, 0xd1, 0xe2, 0xc6,
					0x49, 0x01, 0x17, 0xf3, 0xe1, 0x92, 0xd5, 0x66, 0xa8, 0x3a, 0x43, 0xba, 0x97, 0x96, 0xdf, 0xf6,
					0xb8, 0x69, 0xc6, 0x84, 0x4d, 0xa1, 0x1e, 0x83, 0xb7, 0xfc, 0xc3, 0x7f, 0xbc, 0x94, 0x4a, 0xc5,
					0x85, 0x41, 0x06, 0xd4, 0xfb, 0x7b, 0x1a, 0x4a, 0x45, 0xe1, 0x8e, 0xbe, 0x29, 0x13, 0x92, 0x02,
					0x69, 0xf1, 0xb7, 0xf0, 0x0e, 0xdc, 0xd9, 0xab, 0x67, 0xc2, 0x07, 0x4d, 0x3e, 0xa2, 0xf8, 0xca,
					0x87, 0x01,
				}),
			},
			wantErr: true,
		},
		{
			name: "invalid chunksize",
			args: args{
				key: []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
				ciphertext: bytes.NewReader([]byte{
					0xd3, 0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d,
					0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c, 0x4d, 0x7b, 0xbb, 0x04, 0x07, 0xd1, 0xe2, 0xc6,
					0x49, 0xFF, 0x17, 0xf3, 0xe1, 0x92, 0xd5, 0x66, 0xa8, 0x3a, 0x43, 0xba, 0x97, 0x96, 0xdf, 0xf6,
					0xb8, 0x69, 0xc6, 0x84, 0x4d, 0xa1, 0x1e, 0x83, 0xb7, 0xfc, 0xc3, 0x7f, 0xbc, 0x94, 0x4a, 0xc5,
					0x85, 0x41, 0x06, 0xd4, 0xfb, 0x7b, 0x1a, 0x4a, 0x45, 0xe1, 0x8e, 0xbe, 0x29, 0x13, 0x92, 0x02,
					0x69, 0xf1, 0xb7, 0xf0, 0x0e, 0xdc, 0xd9, 0xab, 0x67, 0xc2, 0x07, 0x4d, 0x3e, 0xa2, 0xf8, 0xca,
					0x87, 0x01,
				}),
			},
			wantErr: true,
		},
		{
			name: "tampered ciphertext",
			args: args{
				key: []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
				ciphertext: bytes.NewReader([]byte{
					0xd3, 0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d,
					0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c, 0x4d, 0x7b, 0xbb, 0x04, 0x07, 0xd1, 0xe2, 0xc6,
					0x49, 0x01, 0xFF, 0xFF, 0xe1, 0x92, 0xd5, 0x66, 0xa8, 0x3a, 0x43, 0xba, 0x97, 0x96, 0xdf, 0xf6,
					0xb8, 0x69, 0xc6, 0x84, 0x4d, 0xa1, 0x1e, 0x83, 0xb7, 0xfc, 0xc3, 0x7f, 0xbc, 0x94, 0x4a, 0xc5,
					0x85, 0x41, 0x06, 0xd4, 0xfb, 0x7b, 0x1a, 0x4a, 0x45, 0xe1, 0x8e, 0xbe, 0x29, 0x13, 0x92, 0x02,
					0x69, 0xf1, 0xb7, 0xf0, 0x0e, 0xdc, 0xd9, 0xab, 0x67, 0xc2, 0x07, 0x4d, 0x3e, 0xa2, 0xf8, 0xca,
					0x87, 0x01,
				}),
			},
			wantErr: true,
		},
		{
			name: "tampered auth tag",
			args: args{
				key: []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
				ciphertext: bytes.NewReader([]byte{
					0xd3, 0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d,
					0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c, 0x4d, 0x7b, 0xbb, 0x04, 0x07, 0xd1, 0xe2, 0xc6,
					0x49, 0x01, 0x17, 0xf3, 0xe1, 0x92, 0xd5, 0x66, 0xa8, 0x3a, 0x43, 0xba, 0x97, 0x96, 0xdf, 0xf6,
					0xb8, 0x69, 0xc6, 0x84, 0x4d, 0xa1, 0x1e, 0x83, 0xb7, 0xfc, 0xc3, 0x7f, 0xbc, 0x94, 0x4a, 0xc5,
					0x85, 0x41, 0x06, 0xd4, 0xfb, 0x7b, 0x1a, 0x4a, 0x45, 0xe1, 0x8e, 0xbe, 0x29, 0x13, 0x92, 0x02,
					0x69, 0xf1, 0xb7, 0xf0, 0x0e, 0xdc, 0xd9, 0xab, 0x67, 0xc2, 0x07, 0x4d, 0x3e, 0xa2, 0xf8, 0xca,
					0xFF, 0xFF,
				}),
			},
			wantErr: true,
		},
		{
			name: "aad mismatch",
			args: args{
				key: []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
				ciphertext: bytes.NewReader([]byte{
					0xd3, 0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d,
					0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c, 0x4d, 0x7b, 0xbb, 0x04, 0x07, 0xd1, 0xe2, 0xc6,
					0x49, 0x01, 0x17, 0xf3, 0xe1, 0x92, 0xd5, 0x66, 0xa8, 0x3a, 0x43, 0xba, 0x97, 0x96, 0xdf, 0xf6,
					0xb8, 0x69, 0xc6, 0x84, 0x4d, 0xa1, 0x1e, 0x83, 0xb7, 0xfc, 0xc3, 0x7f, 0xbc, 0x94, 0x4a, 0xc5,
					0x85, 0x41, 0x06, 0xd4, 0xfb, 0x7b, 0x1a, 0x4a, 0x45, 0xe1, 0x8e, 0xbe, 0x29, 0x13, 0x92, 0x02,
					0x69, 0xf1, 0xb7, 0xf0, 0x0e, 0xdc, 0xd9, 0xab, 0x67, 0xc2, 0x07, 0x4d, 0x3e, 0xa2, 0xf8, 0xca,
					0x87, 0x01,
				}),
				aad: []byte(`{"uid":"8f41b712-663f-48a8-b43c-54cf97a94d1a"}`),
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				key: []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
				ciphertext: bytes.NewReader([]byte{
					0xd3, 0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d,
					0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c, 0x4d, 0x7b, 0xbb, 0x04, 0x07, 0xd1, 0xe2, 0xc6,
					0x49, 0x01, 0x17, 0xf3, 0xe1, 0x92, 0xd5, 0x66, 0xa8, 0x3a, 0x43, 0xba, 0x97, 0x96, 0xdf, 0xf6,
					0xb8, 0x69, 0xc6, 0x84, 0x4d, 0xa1, 0x1e, 0x83, 0xb7, 0xfc, 0xc3, 0x7f, 0xbc, 0x94, 0x4a, 0xc5,
					0x85, 0x41, 0x06, 0xd4, 0xfb, 0x7b, 0x1a, 0x4a, 0x45, 0xe1, 0x8e, 0xbe, 0x29, 0x13, 0x92, 0x02,
					0x69, 0xf1, 0xb7, 0xf0, 0x0e, 0xdc, 0xd9, 0xab, 0x67, 0xc2, 0x07, 0x4d, 0x3e, 0xa2, 0xf8, 0xca,
					0x87, 0x01,
				}),
			},
			want: []byte(`{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}`),
		},
		{
			name: "valid with aad",
			args: args{
				key: []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
				ciphertext: bytes.NewReader([]byte{
					0xd3, 0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d,
					0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c, 0x4d, 0x7b, 0xbb, 0x04, 0x07, 0xd1, 0xe2, 0xc6,
					0x49, 0x01, 0x17, 0xf3, 0xe1, 0x92, 0xd5, 0x66, 0xa8, 0x3a, 0x43, 0xba, 0x97, 0x96, 0xdf, 0xf6,
					0xb8, 0x69, 0xc6, 0x84, 0x4d, 0xa1, 0x1e, 0x83, 0xb7, 0xfc, 0xc3, 0x7f, 0xbc, 0x94, 0x4a, 0xc5,
					0x85, 0x41, 0x06, 0xd4, 0xfb, 0x7b, 0x1a, 0x4a, 0x45, 0xe1, 0x8e, 0xbe, 0x29, 0x13, 0x92, 0x02,
					0x69, 0xf1, 0xd3, 0x6e, 0x96, 0xb5, 0x15, 0x75, 0x83, 0x04, 0xb9, 0xc9, 0x2f, 0xac, 0x4d, 0xfb,
					0xed, 0xf2,
				}),
				aad: []byte(`{"uid":"8f41b712-663f-48a8-b43c-54cf97a94d1a"}`),
			},
			want: []byte(`{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}`),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			err := decrypt(tt.args.key, tt.args.ciphertext, tt.args.aad, &out)
			if (err != nil) != tt.wantErr {
				t.Errorf("decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			got := out.Bytes()
			if report := cmp.Diff(got, tt.want); report != "" {
				t.Errorf("decrypt() = \n%s", report)
			}
		})
	}
}

func TestEncryptDecrypt_256(t *testing.T) {
	t.Parallel()

	// Generate a 1MB file content
	var plaintext bytes.Buffer
	_, err := io.Copy(&plaintext, io.LimitReader(randomness.NewReader(1), 256))
	require.NoError(t, err)

	masterKey := []byte(`hbHt9eWxCN/p0Z#LJmXMb*qV2v;OwY_Db+3^uWS;vz\$7%BW.#LU8Q))n=#pOh+`)

	var encrypted bytes.Buffer
	require.NoError(t, encrypt(randomness.NewReader(2), masterKey, bytes.NewReader(plaintext.Bytes()), nil, &encrypted))
	require.Equal(t, EncryptedLength(plaintext.Len()), encrypted.Len())

	var decrypted bytes.Buffer
	require.NoError(t, decrypt(masterKey, &encrypted, nil, &decrypted))
	require.Equal(t, plaintext.Bytes(), decrypted.Bytes())
}

func TestEncryptDecrypt_1MB(t *testing.T) {
	t.Parallel()

	// Generate a 1MB file content
	var plaintext bytes.Buffer
	_, err := io.Copy(&plaintext, io.LimitReader(randomness.NewReader(1), 1<<20))
	require.NoError(t, err)

	masterKey := []byte(`hbHt9eWxCN/p0Z#LJmXMb*qV2v;OwY_Db+3^uWS;vz\$7%BW.#LU8Q))n=#pOh+`)

	var encrypted bytes.Buffer
	require.NoError(t, encrypt(randomness.NewReader(2), masterKey, bytes.NewReader(plaintext.Bytes()), nil, &encrypted))
	require.Equal(t, EncryptedLength(plaintext.Len()), encrypted.Len())

	var decrypted bytes.Buffer
	require.NoError(t, decrypt(masterKey, &encrypted, nil, &decrypted))
	require.Equal(t, plaintext.Bytes(), decrypted.Bytes())
}

func TestEncryptAndDecrypt(t *testing.T) {
	t.Parallel()

	key := []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB")
	msg := []byte(`{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}`)

	var ciphertext bytes.Buffer
	err := Encrypt(&ciphertext, bytes.NewReader(msg), key)
	require.NoError(t, err)
	require.Equal(t, ciphertext.Len(), EncryptedLength(len(msg)))

	var plaintext bytes.Buffer
	err = Decrypt(&plaintext, &ciphertext, key)
	require.NoError(t, err)
	require.Equal(t, msg, plaintext.Bytes())
}

func TestEncryptAndDecrypt_WithAdditionnalData(t *testing.T) {
	t.Parallel()

	key := []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB")
	msg := []byte(`{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}`)
	aad := []byte(`{"uid":"8f41b712-663f-48a8-b43c-54cf97a94d1a"}`)

	var ciphertext bytes.Buffer
	err := EncryptWithAdditionalData(&ciphertext, bytes.NewReader(msg), key, aad)
	require.NoError(t, err)
	require.Equal(t, ciphertext.Len(), EncryptedLength(len(msg)))

	var plaintext bytes.Buffer
	err = DecryptWithAdditionalData(&plaintext, &ciphertext, key, aad)
	require.NoError(t, err)
	require.Equal(t, msg, plaintext.Bytes())
}

//nolint:errcheck
func BenchmarkEncrypt(b *testing.B) {
	// Generate a 1MB file content
	var plaintext bytes.Buffer
	_, err := io.Copy(&plaintext, io.LimitReader(randomness.NewReader(1), 1<<20))
	require.NoError(b, err)

	b.SetBytes(int64(plaintext.Len()))

	masterKey := []byte(`hbHt9eWxCN/p0Z#LJmXMb*qV2v;OwY_Db+3^uWS;vz\$7%BW.#LU8Q))n=#pOh+`)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypt(rand.Reader, masterKey, bytes.NewReader(plaintext.Bytes()), nil, io.Discard)
	}
}

//nolint:errcheck
func BenchmarkDecrypt(b *testing.B) {
	// Generate a 1MB file content
	var plaintext bytes.Buffer
	_, err := io.Copy(&plaintext, io.LimitReader(randomness.NewReader(1), 1<<20))
	require.NoError(b, err)

	masterKey := []byte(`hbHt9eWxCN/p0Z#LJmXMb*qV2v;OwY_Db+3^uWS;vz\$7%BW.#LU8Q))n=#pOh+`)

	var ciphertext bytes.Buffer
	require.NoError(b, encrypt(rand.Reader, masterKey, bytes.NewReader(plaintext.Bytes()), nil, &ciphertext))
	b.SetBytes(int64(ciphertext.Len()))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decrypt(masterKey, bytes.NewReader(ciphertext.Bytes()), nil, io.Discard)
	}
}
