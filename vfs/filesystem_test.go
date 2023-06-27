// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfirmDir(t *testing.T) {
	t.Parallel()

	root, err := Chroot(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, root.WriteFile("created.dat", []byte(""), 0o600))
	require.NoError(t, root.Mkdir("subdir", 0o755))
	require.NoError(t, root.Symlink("subdir", "symlink"))

	type args struct {
		root FileSystem
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    ConfirmedDir
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "nil root",
			args: args{
				root: nil,
			},
			wantErr: true,
		},
		{
			name: "blank path",
			args: args{
				root: root,
				path: "",
			},
			wantErr: true,
		},
		{
			name: "not-existent",
			args: args{
				root: root,
				path: "not-existent",
			},
			wantErr: true,
		},
		{
			name: "file",
			args: args{
				root: root,
				path: "created.dat",
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				root: root,
				path: "subdir",
			},
			want: ConfirmedDir("/subdir"),
		},
		{
			name: "symlink",
			args: args{
				root: root,
				path: "symlink",
			},
			want: ConfirmedDir("/subdir"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ConfirmDir(tt.args.root, tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConfirmDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ConfirmDir() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChrootFS(t *testing.T) {
	t.Parallel()

	root, err := Chroot(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, root.WriteFile("created.dat", []byte(""), 0o600))
	require.NoError(t, root.Mkdir("subdir", 0o755))
	require.NoError(t, root.Symlink("subdir", "symlink"))

	type args struct {
		root     FileSystem
		rootPath string
	}
	tests := []struct {
		name    string
		args    args
		want    FileSystem
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "nil root",
			args: args{
				root: nil,
			},
			wantErr: true,
		},
		{
			name: "not-existent",
			args: args{
				root:     root,
				rootPath: "not-existent",
			},
			wantErr: true,
		},
		{
			name: "file",
			args: args{
				root:     root,
				rootPath: "created.dat",
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				root:     root,
				rootPath: "subdir",
			},
		},
		{
			name: "symlink",
			args: args{
				root:     root,
				rootPath: "symlink",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ChrootFS(tt.args.root, tt.args.rootPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ChrootFS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
