// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package ioutil

import (
	"errors"
	"io"
	"os"
	"testing"
)

var _ io.Reader = (*zeroReader)(nil)

type zeroReader struct{}

func (dz zeroReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

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
				r:       io.LimitReader(&zeroReader{}, 1024),
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
				r:       io.LimitReader(&zeroReader{}, 2<<20),
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
				r:       io.LimitReader(&zeroReader{}, 1024),
				w:       &fakeWriter{},
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				maxSize: 1 << 20, // 1MB
				r:       io.LimitReader(&zeroReader{}, 1024),
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

func TestLimitCopy_earlyCheck(t *testing.T) {
	t.Parallel()

	r := &zeroReader{}
	w := io.Discard

	pageSize := os.Getpagesize()

	// Run the LimitCopy function with a maximum size limit of 1024 byte.
	n, err := LimitCopy(w, r, uint64(pageSize)*2+1)
	if err == nil {
		t.Error("LimitCopy() error = nil, wantErr true")
	}
	if n != uint64(pageSize)*3 {
		t.Errorf("LimitCopy() n = %v, want %v", n, pageSize)
	}
}
