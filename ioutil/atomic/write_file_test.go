// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package atomic

import (
	"crypto"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/crypto/hashutil"
)

var _ io.Reader = (*fakeReader)(nil)

type fakeReader struct{}

func (fr *fakeReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("error")
}

func getFileHash(t *testing.T, baseDir, filename string) string {
	t.Helper()

	h, err := hashutil.FileHash(os.DirFS(baseDir), filename, crypto.SHA256)
	require.NoError(t, err)

	return hex.EncodeToString(h)
}

func TestWriteFile(t *testing.T) {
	t.Parallel()

	t.Run("not-existent-target", func(t *testing.T) {
		t.Parallel()

		baseDir := t.TempDir()
		require.NoFileExists(t, filepath.Join(baseDir, "not-existent.dat"))
		err := WriteFile(filepath.Join(baseDir, "not-existent.dat"), strings.NewReader("0000-deterministic-for-tests"))
		require.NoError(t, err)
		require.FileExists(t, filepath.Join(baseDir, "not-existent.dat"))

		require.Equal(t, "b7fd0014e215756d96cafb46ae3e241e2e1477065b2a7d39b4484e6bfecf8ad2", getFileHash(t, baseDir, "not-existent.dat"))
	})

	t.Run("existent-target", func(t *testing.T) {
		t.Parallel()

		baseDir := t.TempDir()
		require.NoFileExists(t, filepath.Join(baseDir, "existent.dat"))
		err := WriteFile(filepath.Join(baseDir, "existent.dat"), strings.NewReader("0000-deterministic-for-tests"))
		require.NoError(t, err)

		require.Equal(t, "b7fd0014e215756d96cafb46ae3e241e2e1477065b2a7d39b4484e6bfecf8ad2", getFileHash(t, baseDir, "existent.dat"))

		require.FileExists(t, filepath.Join(baseDir, "existent.dat"))
		err = WriteFile(filepath.Join(baseDir, "existent.dat"), strings.NewReader("0001-deterministic-for-tests"))
		require.NoError(t, err)

		require.Equal(t, "22420150dc3c048360770609e2fde71c2b7a3bd20139c1def5b49a2154d94927", getFileHash(t, baseDir, "existent.dat"))
	})

	t.Run("different-chmod", func(t *testing.T) {
		t.Parallel()

		baseDir := t.TempDir()
		require.NoFileExists(t, filepath.Join(baseDir, "existent.dat"))
		err := WriteFile(filepath.Join(baseDir, "existent.dat"), strings.NewReader("0000-deterministic-for-tests"))
		require.NoError(t, err)
		require.NoError(t, os.Chmod(filepath.Join(baseDir, "existent.dat"), 0o660))

		require.Equal(t, "b7fd0014e215756d96cafb46ae3e241e2e1477065b2a7d39b4484e6bfecf8ad2", getFileHash(t, baseDir, "existent.dat"))

		require.FileExists(t, filepath.Join(baseDir, "existent.dat"))
		err = WriteFile(filepath.Join(baseDir, "existent.dat"), strings.NewReader("0001-deterministic-for-tests"))
		require.NoError(t, err)

		require.Equal(t, "22420150dc3c048360770609e2fde71c2b7a3bd20139c1def5b49a2154d94927", getFileHash(t, baseDir, "existent.dat"))

		fi, err := os.Stat(filepath.Join(baseDir, "existent.dat"))
		require.NoError(t, err)
		require.NotNil(t, fi)
		require.Equal(t, fi.Mode().String(), "-rw-rw----")
	})

	t.Run("symlink", func(t *testing.T) {
		t.Parallel()

		baseDir := t.TempDir()
		require.NoFileExists(t, filepath.Join(baseDir, "symlink-target.dat"))
		err := WriteFile(filepath.Join(baseDir, "symlink-target.dat"), strings.NewReader("0000-deterministic-for-tests"))
		require.NoError(t, err)

		require.Equal(t, "b7fd0014e215756d96cafb46ae3e241e2e1477065b2a7d39b4484e6bfecf8ad2", getFileHash(t, baseDir, "symlink-target.dat"))

		require.NoFileExists(t, filepath.Join(baseDir, "symlink"))
		require.NoError(t, os.Symlink(filepath.Join(baseDir, "symlink-target.dat"), filepath.Join(baseDir, "symlink")))

		err = WriteFile(filepath.Join(baseDir, "symlink"), strings.NewReader("0001-deterministic-for-tests"))
		require.NoError(t, err)

		require.Equal(t, "22420150dc3c048360770609e2fde71c2b7a3bd20139c1def5b49a2154d94927", getFileHash(t, baseDir, "symlink-target.dat"))
	})

	t.Run("reader error", func(t *testing.T) {
		t.Parallel()

		baseDir := t.TempDir()
		require.NoFileExists(t, filepath.Join(baseDir, "reader-error.dat"))
		err := WriteFile(filepath.Join(baseDir, "reader-error.dat"), &fakeReader{})
		require.Error(t, err)
		require.NoFileExists(t, filepath.Join(baseDir, "reader-error.dat"))
	})

	t.Run("reader error with existent file", func(t *testing.T) {
		t.Parallel()

		baseDir := t.TempDir()
		require.NoFileExists(t, filepath.Join(baseDir, "random.dat"))
		err := WriteFile(filepath.Join(baseDir, "random.dat"), strings.NewReader("0000-deterministic-for-tests"))
		require.NoError(t, err)

		require.Equal(t, "b7fd0014e215756d96cafb46ae3e241e2e1477065b2a7d39b4484e6bfecf8ad2", getFileHash(t, baseDir, "random.dat"))

		require.FileExists(t, filepath.Join(baseDir, "random.dat"))
		err = WriteFile(filepath.Join(baseDir, "random.dat"), &fakeReader{})
		require.Error(t, err)

		require.Equal(t, "b7fd0014e215756d96cafb46ae3e241e2e1477065b2a7d39b4484e6bfecf8ad2", getFileHash(t, baseDir, "random.dat"))
	})
}
