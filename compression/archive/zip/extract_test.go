// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package zip

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/crypto/hashutil"
	"github.com/DataDog/go-secure-sdk/vfs"
)

func TestExtract_Golden(t *testing.T) {
	t.Parallel()

	root := os.DirFS("./testdata")

	require.NoError(t, fs.WalkDir(root, "bad", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		f, err := root.Open(path)
		if err != nil {
			return fmt.Errorf("unable to open file: %w", err)
		}

		// Copy in memory (zip lib can't read from a reader directly)
		var zipFile bytes.Buffer
		_, err = io.Copy(&zipFile, f)
		require.NoError(t, err)

		// Create a test instance
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			err := Extract(bytes.NewReader(zipFile.Bytes()), uint64(zipFile.Len()), t.TempDir())
			require.Error(t, err)
		})

		return nil
	}))

	require.NoError(t, fs.WalkDir(root, "good", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// Exclude non zip files
		if !strings.HasSuffix(path, ".zip") {
			return nil
		}

		f, err := root.Open(path)
		if err != nil {
			return fmt.Errorf("unable to open file: %w", err)
		}

		// Copy in memory (zip lib can't read from a reader directly)
		var zipFile bytes.Buffer
		_, err = io.Copy(&zipFile, f)
		require.NoError(t, err)

		// Create a test instance
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			err := Extract(bytes.NewReader(zipFile.Bytes()), uint64(zipFile.Len()), t.TempDir())
			require.NoError(t, err)
		})

		return nil
	}))
}

func TestExtract_WithOverwrite(t *testing.T) {
	t.Parallel()
	root := os.DirFS("./testdata/good/1")

	f1, err := root.Open("1.zip")
	require.NoError(t, err)

	var zipFile bytes.Buffer
	_, err = io.Copy(&zipFile, f1)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	tmpFS, err := vfs.Chroot(tmpDir)
	require.NoError(t, err)

	require.NoError(t, Extract(bytes.NewReader(zipFile.Bytes()), uint64(zipFile.Len()), tmpDir))
	fh, err := hashutil.FileHash(tmpFS, "test.txt", crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2", hex.EncodeToString(fh))

	// Alter evil.sh
	err = tmpFS.WriteFile("test.txt", []byte("this is a new content"), fs.ModePerm)
	require.NoError(t, err)

	fh, err = hashutil.FileHash(tmpFS, "test.txt", crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "145a2d5926d9ff956c22d49e8e6601cefed941cde130cc58756980b13d465609", hex.EncodeToString(fh))

	// Re-extract
	require.NoError(t, Extract(bytes.NewReader(zipFile.Bytes()), uint64(zipFile.Len()), tmpDir, WithOverwriteFilter(
		func(path string, fi fs.FileInfo) bool { return true },
	)))
	fh, err = hashutil.FileHash(tmpFS, "test.txt", crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "145a2d5926d9ff956c22d49e8e6601cefed941cde130cc58756980b13d465609", hex.EncodeToString(fh))
}

func TestExtract_WithoutOverwrite(t *testing.T) {
	t.Parallel()
	root := os.DirFS("./testdata/good/1")

	f1, err := root.Open("1.zip")
	require.NoError(t, err)

	var zipFile bytes.Buffer
	_, err = io.Copy(&zipFile, f1)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	tmpFS, err := vfs.Chroot(tmpDir)
	require.NoError(t, err)

	require.NoError(t, Extract(bytes.NewReader(zipFile.Bytes()), uint64(zipFile.Len()), tmpDir))
	fh, err := hashutil.FileHash(tmpFS, "test.txt", crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2", hex.EncodeToString(fh))

	// Alter evil.sh
	err = tmpFS.WriteFile("test.txt", []byte("this is a new content"), fs.ModePerm)
	require.NoError(t, err)

	fh, err = hashutil.FileHash(tmpFS, "test.txt", crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "145a2d5926d9ff956c22d49e8e6601cefed941cde130cc58756980b13d465609", hex.EncodeToString(fh))

	// Re-extract
	require.NoError(t, Extract(bytes.NewReader(zipFile.Bytes()), uint64(zipFile.Len()), tmpDir, WithOverwriteFilter(
		// Overwrite evil.sh
		func(path string, fi fs.FileInfo) bool { return strings.Contains(path, "evil.sh") },
	)))
	fh, err = hashutil.FileHash(tmpFS, "test.txt", crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2", hex.EncodeToString(fh))
}
