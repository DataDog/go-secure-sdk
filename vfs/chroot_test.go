// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

//nolint:paralleltest // Stateful tests
func TestChroot(t *testing.T) {
	t.Parallel()

	sysFs, err := Chroot(t.TempDir())
	require.NoError(t, err)

	t.Run("create", func(t *testing.T) {
		// Valid
		f, err := sysFs.Create("create.dat")
		require.NoError(t, err)
		require.NotNil(t, f)
		require.NoError(t, f.Close())

		require.True(t, sysFs.Exists("create.dat"))
		require.False(t, sysFs.IsDir("create.dat"))

		// Invalid
		f, err = sysFs.Create(filepath.Join("..", "create.dat"))
		require.ErrorContains(t, err, "fs-security-constraint")
		require.Nil(t, f)
		require.False(t, sysFs.Exists(filepath.Join("..", "create.dat")))
	})

	t.Run("mkdir", func(t *testing.T) {
		// Valid
		require.NoError(t, sysFs.Mkdir("dir1", 0o755))
		require.True(t, sysFs.Exists("dir1"))
		require.True(t, sysFs.IsDir("dir1"))

		// Invalid
		require.ErrorContains(t, sysFs.Mkdir(filepath.Join("..", "dir1"), 0o755), "fs-security-constraint")
		require.False(t, sysFs.Exists(filepath.Join("..", "dir1")))
	})

	t.Run("mkdirAll", func(t *testing.T) {
		// Valid
		require.NoError(t, sysFs.MkdirAll(filepath.Join("dir2", "subdir"), 0o755))
		require.True(t, sysFs.Exists("dir2"))
		require.True(t, sysFs.Exists(filepath.Join("dir2", "subdir")))
		require.True(t, sysFs.IsDir("dir2"))
		require.True(t, sysFs.IsDir(filepath.Join("dir2", "subdir")))

		// Invalid
		require.ErrorContains(t, sysFs.MkdirAll(filepath.Join("..", "dir2", "subdir"), 0o755), "fs-security-constraint")
		require.ErrorContains(t, sysFs.MkdirAll(filepath.Join("dir2", "..", "..", "subdir"), 0o755), "fs-security-constraint")
	})

	t.Run("remove", func(t *testing.T) {
		// Valid
		require.False(t, sysFs.Exists("not-existent"))
		require.Error(t, sysFs.Remove("not-existent"))

		f, err := sysFs.Create("to-be-removed")
		require.NoError(t, err)
		require.NotNil(t, f)
		require.NoError(t, f.Close())

		require.True(t, sysFs.Exists("to-be-removed"))
		require.NoError(t, sysFs.Remove("to-be-removed"))
		require.False(t, sysFs.Exists("to-be-removed"))

		// Invalid
		require.ErrorContains(t, sysFs.Remove(filepath.Join("..", "not-existent")), "fs-security-constraint")
		require.ErrorContains(t, sysFs.Remove(filepath.Join("dir", "..", "..", "not-existent")), "fs-security-constraint")
	})

	t.Run("removeAll", func(t *testing.T) {
		// Valid
		require.False(t, sysFs.Exists("not-existent"))
		require.Error(t, sysFs.Remove("not-existent"))

		require.NoError(t, sysFs.MkdirAll(filepath.Join("subdir", "dir3"), 0o755))
		f, err := sysFs.Create(filepath.Join("subdir", "dir3", "to-be-removed"))
		require.NoError(t, err)
		require.NotNil(t, f)
		require.NoError(t, f.Close())

		require.True(t, sysFs.Exists("subdir"))
		require.True(t, sysFs.Exists(filepath.Join("subdir", "dir3")))
		require.True(t, sysFs.Exists(filepath.Join("subdir", "dir3", "to-be-removed")))

		require.NoError(t, sysFs.RemoveAll("subdir"))

		require.False(t, sysFs.Exists("subdir"))
		require.False(t, sysFs.Exists(filepath.Join("subdir", "dir3")))
		require.False(t, sysFs.Exists(filepath.Join("subdir", "dir3", "to-be-removed")))

		// Invalid
		require.ErrorContains(t, sysFs.RemoveAll(filepath.Join("..", "not-existent")), "fs-security-constraint")
		require.ErrorContains(t, sysFs.RemoveAll(filepath.Join("dir", "..", "..", "not-existent")), "fs-security-constraint")
	})

	t.Run("open", func(t *testing.T) {
		// Valid
		f, err := sysFs.Open("create.dat")
		require.NoError(t, err)
		require.NotNil(t, f)
		require.NoError(t, f.Close())

		require.True(t, sysFs.Exists("create.dat"))
		require.False(t, sysFs.IsDir("create.dat"))

		// Invalid
		f, err = sysFs.Open(filepath.Join("..", "create.dat"))
		require.ErrorContains(t, err, "fs-security-constraint")
		require.Nil(t, f)
		require.False(t, sysFs.Exists(filepath.Join("..", "create.dat")))
	})

	t.Run("stat", func(t *testing.T) {
		// Valid
		fi, err := sysFs.Stat("create.dat")
		require.NoError(t, err)
		require.NotNil(t, fi)

		// Invalid
		fi, err = sysFs.Stat(filepath.Join("..", "create.dat"))
		require.ErrorContains(t, err, "fs-security-constraint")
		require.Nil(t, fi)
	})

	t.Run("isDir", func(t *testing.T) {
		// Valid
		require.False(t, sysFs.IsDir("create.dat"))
		require.True(t, sysFs.IsDir("dir1"))

		// Invalid
		require.False(t, sysFs.IsDir("../create.dat"))
		require.False(t, sysFs.IsDir("../dir1"))
	})

	t.Run("readDir", func(t *testing.T) {
		// Valid
		entries, err := sysFs.ReadDir("create.dat")
		require.Error(t, err)
		require.Empty(t, entries)

		entries, err = sysFs.ReadDir("/")
		require.NoError(t, err)
		require.NotEmpty(t, entries)

		// Invalid
		entries, err = sysFs.ReadDir(filepath.Join("..", "dir1"))
		require.ErrorContains(t, err, "fs-security-constraint")
		require.Empty(t, entries)
	})

	t.Run("exists", func(t *testing.T) {
		// Valid
		require.True(t, sysFs.Exists("create.dat"))
		require.True(t, sysFs.Exists("dir1"))

		// Invalid
		require.False(t, sysFs.Exists("../create.dat"))
		require.False(t, sysFs.Exists("../dir1"))
	})

	t.Run("glob", func(t *testing.T) {
		// Valid
		entries, err := sysFs.Glob("dir*")
		require.NoError(t, err)
		require.NotEmpty(t, entries)

		// Invalid
		entries, err = sysFs.Glob("../dir*")
		require.NoError(t, err)
		require.Empty(t, entries)
	})

	t.Run("readFile", func(t *testing.T) {
		// Valid
		p, err := sysFs.ReadFile("create.dat")
		require.NoError(t, err)
		require.Empty(t, p)

		// Invalid
		p, err = sysFs.ReadFile(filepath.Join("..", "create.dat"))
		require.ErrorContains(t, err, "fs-security-constraint")
		require.Nil(t, p)
	})

	t.Run("writeFile", func(t *testing.T) {
		// Valid
		require.NoError(t, sysFs.WriteFile("writed.dat", []byte("test"), 0o600))
		require.True(t, sysFs.Exists("writed.dat"))

		// Invalid
		require.ErrorContains(t, sysFs.WriteFile(filepath.Join("..", "writed.dat"), []byte("test"), 0o600), "fs-security-constraint")
	})

	t.Run("walkDir", func(t *testing.T) {
		// Valid
		require.NoError(t, sysFs.WalkDir("/", func(path string, info fs.DirEntry, err error) error { return err }))

		// Invalid
		require.ErrorContains(t, sysFs.WalkDir("../", func(path string, info fs.DirEntry, err error) error { return err }), "fs-security-constraint")
	})

	t.Run("chmod", func(t *testing.T) {
		// Valid
		require.NoError(t, sysFs.Chmod("create.dat", 0o600))

		// Invalid
		require.ErrorContains(t, sysFs.Chmod(filepath.Join("..", "create.dat"), 0o600), "fs-security-constraint")
	})

	t.Run("symlink", func(t *testing.T) {
		// Valid
		require.NoError(t, sysFs.Symlink("create.dat", "symlink"))

		// Invalid
		require.ErrorContains(t, sysFs.Symlink(filepath.Join("..", "create.dat"), "badsymlink"), "fs-security-constraint")
		require.ErrorContains(t, sysFs.Symlink("create.dat", filepath.Join("..", "badsymlink")), "fs-security-constraint")
	})

	t.Run("hardlink", func(t *testing.T) {
		// Valid
		require.NoError(t, sysFs.Link("create.dat", "hardlink"))

		// Invalid
		require.ErrorContains(t, sysFs.Link(filepath.Join("..", "create.dat"), "badhardlink"), "fs-security-constraint")
		require.ErrorContains(t, sysFs.Link("create.dat", filepath.Join("..", "badhardlink")), "fs-security-constraint")
	})

	t.Run("resolve", func(t *testing.T) {
		d, p, err := sysFs.Resolve("")
		require.NoError(t, err)
		require.Empty(t, p)
		require.NotNil(t, d)
		require.Equal(t, FakeRoot, d.String())
	})
}
