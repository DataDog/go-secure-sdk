package encryption

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/awnumar/memguard"
	"github.com/stretchr/testify/require"
)

func Test_SealParse(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := SealSecretCabin(&out, memguard.NewBufferFromBytes([]byte("0123456789")), []byte("testing-password"))
	require.NoError(t, err)
	require.NotEmpty(t, out)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		lb, err := ParseSecretCabin(out.Bytes(), []byte("testing-password"))
		require.NoError(t, err)
		require.NotNil(t, lb)
		require.Equal(t, []byte("0123456789"), lb.Bytes())
	})

	t.Run("password too short", func(t *testing.T) {
		t.Parallel()

		lb, err := ParseSecretCabin(out.Bytes(), []byte(""))
		require.Error(t, err)
		require.Nil(t, lb)
	})

	t.Run("invalid password", func(t *testing.T) {
		t.Parallel()

		lb, err := ParseSecretCabin(out.Bytes(), []byte("wrong"))
		require.Error(t, err)
		require.Nil(t, lb)
	})
}

func TestParseSecretCabin(t *testing.T) {
	t.Parallel()

	type args struct {
		data     []byte
		password []byte
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
			name: "empty",
			args: args{
				data: []byte(`{}`),
			},
			wantErr: true,
		},
		{
			name: "password too short",
			args: args{
				data:     []byte(`{"kdf":{"name":"scrypt","version":1,"salt":"Ca5mtkSloMp8IzG0BhLOtg=="},"cipher":{"name":"datadog/d2"},"ciphertext":"0taje9X41P4mbIEA+so9zwWJEC7yhhQ16tAhU9pY0cXSMpJDgjA/GDSZbSz/e82p4x2GRD8BomgKZv1jgRHkBtdDQwHo"}`),
				password: []byte(``),
			},
			wantErr: true,
		},
		{
			name: "invalid JSON",
			args: args{
				data:     []byte(`{`),
				password: []byte(`0123456789012345`),
			},
			wantErr: true,
		},
		{
			name: "unsupported KDF",
			args: args{
				data:     []byte(`{"kdf":{"name":"unknown","version":1,"salt":"Ca5mtkSloMp8IzG0BhLOtg=="},"cipher":{"name":"datadog/d2"},"ciphertext":"0taje9X41P4mbIEA+so9zwWJEC7yhhQ16tAhU9pY0cXSMpJDgjA/GDSZbSz/e82p4x2GRD8BomgKZv1jgRHkBtdDQwHo"}`),
				password: []byte(`0123456789012345`),
			},
			wantErr: true,
		},
		{
			name: "tampered KDF settings",
			args: args{
				data:     []byte(`{"kdf":{"name":"scrypt","version":99,"salt":"Ca5mtkSloMp8IzG0BhLOtg=="},"cipher":{"name":"datadog/d2"},"ciphertext":"0taje9X41P4mbIEA+so9zwWJEC7yhhQ16tAhU9pY0cXSMpJDgjA/GDSZbSz/e82p4x2GRD8BomgKZv1jgRHkBtdDQwHo"}`),
				password: []byte(`0123456789012345`),
			},
			wantErr: true,
		},
		{
			name: "empty salt",
			args: args{
				data:     []byte(`{"kdf":{"name":"scrypt","version":1,"salt":""},"cipher":{"name":"datadog/d2"},"ciphertext":"0taje9X41P4mbIEA+so9zwWJEC7yhhQ16tAhU9pY0cXSMpJDgjA/GDSZbSz/e82p4x2GRD8BomgKZv1jgRHkBtdDQwHo"}`),
				password: []byte(`0123456789012345`),
			},
			wantErr: true,
		},
		{
			name: "tampered salt",
			args: args{
				data:     []byte(`{"kdf":{"name":"scrypt","version":1,"salt":"Ca5m00SloMp8IzG0BhLOtg=="},"cipher":{"name":"datadog/d2"},"ciphertext":"0taje9X41P4mbIEA+so9zwWJEC7yhhQ16tAhU9pY0cXSMpJDgjA/GDSZbSz/e82p4x2GRD8BomgKZv1jgRHkBtdDQwHo"}`),
				password: []byte(`0123456789012345`),
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				data:     []byte(`{"kdf":{"name":"scrypt","version":1,"salt":"Ca5mtkSloMp8IzG0BhLOtg=="},"cipher":{"name":"datadog/d2"},"ciphertext":"0taje9X41P4mbIEA+so9zwWJEC7yhhQ16tAhU9pY0cXSMpJDgjA/GDSZbSz/e82p4x2GRD8BomgKZv1jgRHkBtdDQwHo"}`),
				password: []byte(`0123456789012345`),
			},
			want: []byte("super-secret"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseSecretCabin(tt.args.data, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSecretCabin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				raw := got.Bytes()
				if !reflect.DeepEqual(raw, tt.want) {
					t.Errorf("ParseSecretCabin() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestSealSecretCabin(t *testing.T) {
	t.Parallel()

	type args struct {
		secret   *memguard.LockedBuffer
		password []byte
	}
	tests := []struct {
		name    string
		args    args
		wantW   string
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "password too short",
			args: args{
				secret:   memguard.NewBufferFromBytes([]byte("super-secret")),
				password: []byte(""),
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				secret:   memguard.NewBufferFromBytes([]byte("super-secret")),
				password: []byte("0123456789012345"),
			},
			wantW: `{"kdf":{"name":"scrypt","version":1,"salt":"Ca5mtkSloMp8IzG0BhLOtg=="},"cipher":{"name":"datadog/d2"},"ciphertext":"0taje9X41P4mbIEA+so9zwWJEC7yhhQ16tAhU9pY0cXSMpJDgjA/GDSZbSz/e82p4x2GRD8BomgKZv1jgRHkBtdDQwHo"}`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := &bytes.Buffer{}
			if err := SealSecretCabin(w, tt.args.secret, tt.args.password); (err != nil) != tt.wantErr {
				t.Errorf("SealSecretCabin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
