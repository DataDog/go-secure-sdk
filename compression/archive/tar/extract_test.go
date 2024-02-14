// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package tar

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/crypto/hashutil"
	"github.com/DataDog/go-secure-sdk/vfs"
)

func TestExtract_Golden(t *testing.T) {
	root := os.DirFS("testdata")

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

		// Create a test instance
		t.Run(path, func(t *testing.T) {
			err := Extract(f, t.TempDir())
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

		f, err := root.Open(path)
		if err != nil {
			return fmt.Errorf("unable to open file: %w", err)
		}

		// Create a test instance
		t.Run(path, func(t *testing.T) {
			err := Extract(f, t.TempDir())
			require.NoError(t, err)
		})

		return nil
	}))
}

func TestExtract_WithOverwrite(t *testing.T) {
	t.Parallel()
	root := os.DirFS("./testdata/good")

	f1, err := root.Open("archive.tar")
	require.NoError(t, err)

	tmpDir := t.TempDir()
	tmpFS, err := vfs.Chroot(tmpDir)
	require.NoError(t, err)

	require.NoError(t, Extract(f1, tmpDir))
	fh, err := hashutil.FileHash(tmpFS, "evil.sh", crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "e043927118884a50b17102ae31d3e0e5d6478d52439727eb3f66fc8f99d13a73", hex.EncodeToString(fh))

	// Alter evil.sh
	err = tmpFS.WriteFile("evil.sh", []byte("this is a new content"), fs.ModePerm)
	require.NoError(t, err)

	fh, err = hashutil.FileHash(tmpFS, "evil.sh", crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "145a2d5926d9ff956c22d49e8e6601cefed941cde130cc58756980b13d465609", hex.EncodeToString(fh))

	// Re-extract
	f2, err := root.Open("archive.tar")
	require.NoError(t, err)

	require.NoError(t, Extract(f2, tmpDir, WithOverwriteFilter(
		func(path string, fi fs.FileInfo) bool { return true },
	)))
	fh, err = hashutil.FileHash(tmpFS, "evil.sh", crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "145a2d5926d9ff956c22d49e8e6601cefed941cde130cc58756980b13d465609", hex.EncodeToString(fh))
}

func TestExtract_WithoutOverwrite(t *testing.T) {
	t.Parallel()
	root := os.DirFS("./testdata/good")

	f1, err := root.Open("archive.tar")
	require.NoError(t, err)

	tmpDir := t.TempDir()
	tmpFS, err := vfs.Chroot(tmpDir)
	require.NoError(t, err)

	require.NoError(t, Extract(f1, tmpDir))
	fh, err := hashutil.FileHash(tmpFS, "evil.sh", crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "e043927118884a50b17102ae31d3e0e5d6478d52439727eb3f66fc8f99d13a73", hex.EncodeToString(fh))

	// Alter evil.sh
	err = tmpFS.WriteFile("evil.sh", []byte("this is a new content"), fs.ModePerm)
	require.NoError(t, err)

	fh, err = hashutil.FileHash(tmpFS, "evil.sh", crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "145a2d5926d9ff956c22d49e8e6601cefed941cde130cc58756980b13d465609", hex.EncodeToString(fh))

	// Re-extract
	f2, err := root.Open("archive.tar")
	require.NoError(t, err)

	require.NoError(t, Extract(f2, tmpDir, WithOverwriteFilter(
		// Overwrite test.txt
		func(path string, fi fs.FileInfo) bool { return strings.Contains(path, "text.txt") },
	)))
	fh, err = hashutil.FileHash(tmpFS, "evil.sh", crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "e043927118884a50b17102ae31d3e0e5d6478d52439727eb3f66fc8f99d13a73", hex.EncodeToString(fh))
}
