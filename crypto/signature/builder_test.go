// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package signature

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func mustEncodePrivateKey(t *testing.T, pk any) []byte {
	t.Helper()

	raw, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: raw,
	})
}

func mustEncodePublicKey(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()

	raw, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: raw,
	})
}

func TestBuilders(t *testing.T) {
	t.Parallel()

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	testCases := []struct {
		Private crypto.Signer
		Public  crypto.PublicKey
	}{
		{Private: ecPriv, Public: ecPriv.Public()},
		{Private: edPriv, Public: edPub},
	}

	for _, tc := range testCases {
		// tt aliases the tc instance to prevent tc reuse during parallel testing
		// which could cause fuzzy results.
		tt := tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			s1, err := FromPrivateKey(tt.Private)
			assert.NoError(t, err)
			assert.NotNil(t, s1)

			privPem := mustEncodePrivateKey(t, tt.Private)
			s2, err := FromPrivateKeyPEM(bytes.NewReader(privPem))
			assert.NoError(t, err)
			assert.NotNil(t, s2)

			v1, err := FromPublicKey(tt.Public)
			assert.NoError(t, err)
			assert.NotNil(t, v1)

			pubPem := mustEncodePublicKey(t, tt.Public)
			v2, err := FromPublicKeyPEM(bytes.NewReader(pubPem))
			assert.NoError(t, err)
			assert.NotNil(t, v2)

			// Ensure equivalence
			msg := []byte("test")
			sig1, err := s1.Sign(msg)
			assert.NoError(t, err)
			assert.NoError(t, v2.Verify(msg, sig1))

			sig2, err := s2.Sign(msg)
			assert.NoError(t, err)
			assert.NoError(t, v1.Verify(msg, sig2))
		})
	}
}

func TestFromPublicKey(t *testing.T) {
	t.Parallel()

	pk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	type args struct {
		pub crypto.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    Verifier
		wantErr bool
	}{
		{
			name: "nil",
			args: args{
				pub: nil,
			},
			wantErr: true,
		},
		{
			name: "unsupported rsa",
			args: args{
				pub: &rsa.PublicKey{},
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "ecdsa",
			args: args{
				pub: pk1.Public(),
			},
			wantErr: false,
		},
		{
			name: "ed25519",
			args: args{
				pub: pub2,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := FromPublicKey(tt.args.pub)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

var _ io.Reader = (*fakeReader)(nil)

type fakeReader struct{}

func (r *fakeReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("test")
}

var (
	testEd25519PubKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----
`

	testEd25519PrivKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----`

	testECDSAPrivKey = `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCwS7FZqyX0Xbk1hvCp
gCuVKJL/NjF0B8QCpzWbGCXmPA==
-----END PRIVATE KEY-----`

	testECDSAPubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh4GrAmD45m+8x7VF4W3DjSBxIRVu
zEtcyFbY0FtEDPoZ974Ayk8tWjytNkolc5oCNwHhfQ6QJ4brchPbOgqFOg==
-----END PUBLIC KEY-----`
)

func TestFromPublicKeyPEM(t *testing.T) {
	t.Parallel()

	type args struct {
		r io.Reader
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
			name: "reader error",
			args: args{
				r: &fakeReader{},
			},
			wantErr: true,
		},
		{
			name: "blank PEM",
			args: args{
				r: strings.NewReader(""),
			},
			wantErr: true,
		},
		{
			name: "unexpected PEM type",
			args: args{
				r: strings.NewReader(testEd25519PrivKey),
			},
			wantErr: true,
		},
		{
			name: "swapped PEM type",
			args: args{
				r: strings.NewReader(strings.Replace(testEd25519PrivKey, "PRIVATE", "PUBLIC", 2)),
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "ed25519",
			args: args{
				r: strings.NewReader(testEd25519PubKey),
			},
			wantErr: false,
		},
		{
			name: "ecdsa",
			args: args{
				r: strings.NewReader(testECDSAPubKey),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := FromPublicKeyPEM(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromPublicKeyPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestFromPrivateKey(t *testing.T) {
	t.Parallel()

	pk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, pk2, _ := ed25519.GenerateKey(rand.Reader)

	type args struct {
		pk crypto.Signer
	}
	tests := []struct {
		name    string
		args    args
		want    Signer
		wantErr bool
	}{
		{
			name: "nil",
			args: args{
				pk: nil,
			},
			wantErr: true,
		},
		{
			name: "unsupported rsa",
			args: args{
				pk: &rsa.PrivateKey{},
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "ecdsa",
			args: args{
				pk: pk1,
			},
			wantErr: false,
		},
		{
			name: "ed25519",
			args: args{
				pk: pk2,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := FromPrivateKey(tt.args.pk)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestFromPrivateKeyPEM(t *testing.T) {
	t.Parallel()

	type args struct {
		r io.Reader
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
			name: "reader error",
			args: args{
				r: &fakeReader{},
			},
			wantErr: true,
		},
		{
			name: "blank PEM",
			args: args{
				r: strings.NewReader(""),
			},
			wantErr: true,
		},
		{
			name: "unexpected PEM type",
			args: args{
				r: strings.NewReader(testEd25519PubKey),
			},
			wantErr: true,
		},
		{
			name: "swapped PEM type",
			args: args{
				r: strings.NewReader(strings.Replace(testEd25519PubKey, "PUBLIC", "PRIVATE", 2)),
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "ed25519",
			args: args{
				r: strings.NewReader(testEd25519PrivKey),
			},
			wantErr: false,
		},
		{
			name: "ecdsa",
			args: args{
				r: strings.NewReader(testECDSAPrivKey),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := FromPrivateKeyPEM(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromPrivateKeyPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
