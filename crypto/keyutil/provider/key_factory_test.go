package provider

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStaticSymmetricSecret(t *testing.T) {
	t.Parallel()

	type args struct {
		raw      []byte
		purposes []KeyPurpose
		alias    KeyAlias
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "conflictual purposes",
			args: args{
				raw: []byte("this is a tasting value"),
				purposes: []KeyPurpose{
					EncryptionPurpose,
					SignaturePurpose,
				},
				alias: KeyAlias("testing/key"),
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				raw: []byte("this is a tasting value"),
				purposes: []KeyPurpose{
					EncryptionPurpose,
				},
				alias: KeyAlias("testing/key"),
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kf := StaticSymmetricSecret(tt.args.raw, tt.args.purposes...)
			got, err := kf(tt.args.alias)
			if tt.wantErr != (err != nil) {
				t.Errorf("got err, %v", err)
			}

			if got != nil {
				require.Equal(t, tt.args.alias, got.Alias())
			}
		})
	}
}

func TestStaticPublicKey(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	type args struct {
		key      crypto.PublicKey
		purposes []KeyPurpose
		alias    KeyAlias
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "conflictual purposes",
			args: args{
				key: pub,
				purposes: []KeyPurpose{
					EncryptionPurpose,
					SignaturePurpose,
				},
				alias: KeyAlias("testing/key"),
			},
			wantErr: true,
		},
		{
			name: "unsupported key type",
			args: args{
				key: []byte("test"),
				purposes: []KeyPurpose{
					SignaturePurpose,
				},
				alias: KeyAlias("testing/key"),
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				key: pub,
				purposes: []KeyPurpose{
					SignaturePurpose,
				},
				alias: KeyAlias("testing/key"),
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kf := StaticPublicKey(tt.args.key, tt.args.purposes...)
			got, err := kf(tt.args.alias)
			if tt.wantErr != (err != nil) {
				t.Errorf("got err, %v", err)
			}

			if got != nil {
				require.Equal(t, tt.args.alias, got.Alias())
			}
		})
	}
}

func TestStaticPrivateKey(t *testing.T) {
	t.Parallel()

	_, pk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	type args struct {
		key      crypto.Signer
		purposes []KeyPurpose
		alias    KeyAlias
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "conflictual purposes",
			args: args{
				key: pk,
				purposes: []KeyPurpose{
					EncryptionPurpose,
					SignaturePurpose,
				},
				alias: KeyAlias("testing/key"),
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				key: pk,
				purposes: []KeyPurpose{
					SignaturePurpose,
				},
				alias: KeyAlias("testing/key"),
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kf := StaticPrivateKey(tt.args.key, tt.args.purposes...)
			got, err := kf(tt.args.alias)
			if tt.wantErr != (err != nil) {
				t.Errorf("got err, %v", err)
			}

			if got != nil {
				require.Equal(t, tt.args.alias, got.Alias())
			}
		})
	}
}
