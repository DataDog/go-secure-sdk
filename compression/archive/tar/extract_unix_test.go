// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package tar

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/compression/archive/tar/builder"
	"github.com/DataDog/go-secure-sdk/vfs"
)

func TestExtract_WithRestoreOwner(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	b, err := builder.New(out).With(
		builder.File("file.txt", strings.NewReader("hello, world"),
			builder.WithUID(os.Getuid()),
			builder.WithGID(os.Getgid()),
		),
	)
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Close())

	tmpDir := t.TempDir()
	require.NoError(t, Extract(out, tmpDir, WithRestoreOwner(true)))

	// Create a new file system
	root, err := vfs.Chroot(tmpDir)
	require.NoError(t, err)

	// Check the file
	fi, err := root.Lstat("file.txt")
	require.NoError(t, err)
	require.NotNil(t, fi.Sys())
	require.IsType(t, &syscall.Stat_t{}, fi.Sys())
	require.Equal(t, os.Getuid(), int(fi.Sys().(*syscall.Stat_t).Uid))
	require.Equal(t, os.Getgid(), int(fi.Sys().(*syscall.Stat_t).Gid))
}

func TestExtract_WithRestoreOwner_WithRemapper(t *testing.T) {
	t.Parallel()

	t.Run("remap", func(t *testing.T) {
		t.Parallel()

		out := &bytes.Buffer{}
		b, err := builder.New(out).With(
			builder.File("file.txt", strings.NewReader("hello, world"),
				builder.WithUID(0),
				builder.WithGID(0),
			),
		)
		require.NoError(t, err)
		require.NotNil(t, b)
		require.NoError(t, b.Close())

		tmpDir := t.TempDir()
		require.NoError(t, Extract(out, tmpDir, WithRestoreOwner(true), WithUIDGIDMapperFunc(func(uid, gid int) (int, int, error) {
			return os.Getuid(), os.Getgid(), nil
		})))

		// Create a new file system
		root, err := vfs.Chroot(tmpDir)
		require.NoError(t, err)

		// Check the file
		fi, err := root.Lstat("file.txt")
		require.NoError(t, err)
		require.NotNil(t, fi.Sys())
		require.IsType(t, &syscall.Stat_t{}, fi.Sys())
		require.Equal(t, os.Getuid(), int(fi.Sys().(*syscall.Stat_t).Uid))
		require.Equal(t, os.Getgid(), int(fi.Sys().(*syscall.Stat_t).Gid))
	})

	t.Run("remap_error", func(t *testing.T) {
		t.Parallel()

		out := &bytes.Buffer{}
		b, err := builder.New(out).With(
			builder.File("file.txt", strings.NewReader("hello, world"),
				builder.WithUID(0),
				builder.WithGID(0),
			),
		)
		require.NoError(t, err)
		require.NotNil(t, b)
		require.NoError(t, b.Close())

		tmpDir := t.TempDir()
		require.Error(t, Extract(out, tmpDir, WithRestoreOwner(true), WithUIDGIDMapperFunc(func(uid, gid int) (int, int, error) {
			return -1, -1, fmt.Errorf("unable to map UID/GID")
		})))
	})

	t.Run("remap_invalid", func(t *testing.T) {
		t.Parallel()

		out := &bytes.Buffer{}
		b, err := builder.New(out).With(
			builder.File("file.txt", strings.NewReader("hello, world"),
				builder.WithUID(0),
				builder.WithGID(0),
			),
		)
		require.NoError(t, err)
		require.NotNil(t, b)
		require.NoError(t, b.Close())

		tmpDir := t.TempDir()
		require.Error(t, Extract(out, tmpDir, WithRestoreOwner(true), WithUIDGIDMapperFunc(func(uid, gid int) (int, int, error) {
			return -1, -1, nil
		})))
	})
}
