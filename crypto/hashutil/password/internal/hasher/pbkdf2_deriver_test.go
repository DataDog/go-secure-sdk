package hasher

import (
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_pbkdf2Deriver_Hash(t *testing.T) {
	t.Parallel()

	type fields struct {
		version    uint8
		h          func() hash.Hash
		salt       []byte
		iterations uint32
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
				version:    1,
				h:          sha512.New,
				salt:       []byte(`GsdYAMk@Lg5#\'uivVh)?</[ndjk%zv5`),
				iterations: 650000,
			},
			args: args{
				password: []byte("this is a test password"),
			},
			wantErr: false,
			want: &Metadata{
				Algorithm: uint8(Pbkdf2HmacSha512),
				Version:   1,
				Salt:      []byte(`GsdYAMk@Lg5#\'uivVh)?</[ndjk%zv5`),
				Hash: []byte{
					0xb9, 0xb0, 0x42, 0xaf, 0x74, 0xa2, 0xb6, 0x53, 0xcc, 0x67, 0xfa, 0x09, 0x2b, 0x87, 0x58, 0xf3,
					0xd9, 0xfa, 0x8a, 0xea, 0xd3, 0xb0, 0x01, 0xbb, 0x25, 0xcb, 0x72, 0xd4, 0x6e, 0x6f, 0x27, 0xc5,
					0xb0, 0x29, 0x65, 0x4b, 0xb8, 0x47, 0xe6, 0x89, 0xa6, 0x42, 0x5b, 0xfe, 0xc1, 0x57, 0x6c, 0x2e,
					0x2a, 0x69, 0x6f, 0x2b, 0x49, 0x16, 0x65, 0x9c, 0x04, 0xe9, 0xbf, 0xa6, 0x33, 0xf1, 0x72, 0xd7,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newPbkdf2Deriver(
				tt.fields.version,
				tt.fields.salt,
				tt.fields.iterations,
			)
			got, err := d.Hash(tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("pbkdf2Deriver.Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if report := cmp.Diff(tt.want, got); report != "" {
				t.Errorf("pbkdf2Deriver.Hash() = \n%s", report)
			}
		})
	}
}
