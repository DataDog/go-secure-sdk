// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package canonicalization

import (
	"bytes"
	"reflect"
	"testing"
)

func TestPreAuthenticationEncoding(t *testing.T) {
	t.Parallel()

	type args struct {
		pieces [][]byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "empty",
			args: args{
				pieces: nil,
			},
			want: nil,
		},
		{
			name: "too many piece",
			args: args{
				pieces: func() [][]byte {
					return make([][]byte, maxPieceCount+1)
				}(),
			},
			wantErr: true,
			want:    nil,
		},
		{
			name: "piece too large",
			args: args{
				pieces: func() [][]byte {
					largePiece := bytes.Repeat([]byte{0x41}, maxPieceSize+1)
					return [][]byte{
						largePiece,
					}
				}(),
			},
			wantErr: true,
			want:    nil,
		},
		{
			name: "one",
			args: args{
				pieces: [][]byte{
					[]byte("test"),
				},
			},
			want: []byte{
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Count
				0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Length
				't', 'e', 's', 't',
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := PreAuthenticationEncoding(tt.args.pieces...)
			if tt.wantErr != (err != nil) {
				t.Errorf("PreAuthenticationEncoding() returned an unexpected error, got %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PreAuthenticationEncoding() = %v, want %v", got, tt.want)
			}
		})
	}
}

//nolint:errcheck
func BenchmarkPreAuthenticationEncoding(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PreAuthenticationEncoding(
			[]byte("datadog-signature-v1"),
			[]byte("123456789"),
			[]byte{0xAB, 0xBC, 0xCD, 0xDE},
		)
	}
}

//nolint:errcheck
func FuzzPreAuthenticationEncoding(f *testing.F) {
	f.Fuzz(func(t *testing.T, a, b, c, d []byte) {
		PreAuthenticationEncoding(a, b, c, d)
	})
}
