package hasher

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_argonDeriver_Hash(t *testing.T) {
	t.Parallel()

	type fields struct {
		version uint8
		salt    []byte
		time    uint32
		memory  uint32
		threads uint8
	}
	type args struct {
		password []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Metadata
		wantErr bool
	}{
		{
			name: "valid - v1",
			fields: fields{
				version: 1,
				salt:    []byte(`GsdYAMk@Lg5#\'uivVh)?</[ndjk%zv5`),
				time:    8,
				memory:  64 * 1024,
				threads: 2,
			},
			args: args{
				password: []byte("this is a test password"),
			},
			wantErr: false,
			want: &Metadata{
				Algorithm: uint8(Argon2id),
				Version:   1,
				Salt:      []byte(`GsdYAMk@Lg5#\'uivVh)?</[ndjk%zv5`),
				Hash: []byte{
					0xc9, 0x9e, 0x41, 0x44, 0x03, 0x99, 0x78, 0x71, 0x65, 0xc0, 0x34, 0x2b, 0x0e, 0x1a, 0xa5, 0x2f,
					0x3f, 0x35, 0xe2, 0x79, 0xe9, 0x3e, 0x93, 0x53, 0x0f, 0xf5, 0x42, 0xf3, 0x71, 0xac, 0xe6, 0xd3,
					0x97, 0x5b, 0x05, 0x6a, 0x55, 0x0a, 0x0c, 0xf1, 0x4f, 0xf8, 0x4a, 0xa5, 0x1b, 0xbe, 0x2e, 0x8c,
					0x88, 0x12, 0x9a, 0x50, 0x3f, 0x66, 0xca, 0x7b, 0x30, 0x29, 0x53, 0x8d, 0x90, 0x8b, 0x7a, 0xd1,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newArgon2Deriver(
				tt.fields.version,
				tt.fields.salt,
				tt.fields.time,
				tt.fields.memory,
				tt.fields.threads,
			)
			got, err := d.Hash(tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("argonDeriver.Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if report := cmp.Diff(tt.want, got); report != "" {
				t.Errorf("pbkdf2Deriver.Hash() = \n%s", report)
			}
		})
	}
}
