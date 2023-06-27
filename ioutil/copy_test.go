// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package ioutil

import (
	"errors"
	"io"
	"testing"

	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

var _ io.Reader = (*fakeReader)(nil)

type fakeReader struct{}

func (fr *fakeReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("error")
}

var _ io.Writer = (*fakeWriter)(nil)

type fakeWriter struct{}

func (fw *fakeWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("error")
}

func TestLimitCopy(t *testing.T) {
	t.Parallel()

	type args struct {
		maxSize uint64
		r       io.Reader
		w       io.Writer
	}
	tests := []struct {
		name    string
		args    args
		wantW   string
		wantErr bool
	}{
		{
			name: "nil writer",
			args: args{
				maxSize: 1 << 20, // 1MB
				w:       nil,
				r:       io.LimitReader(randomness.Reader, 1024),
			},
			wantErr: true,
		},
		{
			name: "nil reader",
			args: args{
				maxSize: 1 << 20, // 1MB
				w:       io.Discard,
				r:       nil,
			},
			wantErr: true,
		},
		{
			name: "too large",
			args: args{
				maxSize: 1 << 20, // 1MB
				r:       io.LimitReader(randomness.Reader, 2<<20),
				w:       io.Discard,
			},
			wantErr: true,
		},
		{
			name: "read error",
			args: args{
				maxSize: 1 << 20, // 1MB
				r:       &fakeReader{},
				w:       io.Discard,
			},
			wantErr: true,
		},
		{
			name: "write error",
			args: args{
				maxSize: 1 << 20, // 1MB
				r:       io.LimitReader(randomness.Reader, 1024),
				w:       &fakeWriter{},
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				maxSize: 1 << 20, // 1MB
				r:       io.LimitReader(randomness.Reader, 1024),
				w:       io.Discard,
			},
		},
	}
	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := LimitCopy(tc.args.w, tc.args.r, tc.args.maxSize); (err != nil) != tc.wantErr {
				t.Errorf("LimitCopy() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
		})
	}
}
