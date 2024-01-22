package vfs

import (
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

//nolint:paralleltest // Disable parallel test for filesystem
func TestOSFS(t *testing.T) {
	// Ensure the real path to be used.
	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	// Build filesystem instance
	sysFs := OS()

	t.Run("file operations", func(t *testing.T) {
		testFilePath := filepath.Join(tmpDir, "create.dat")
		require.False(t, sysFs.Exists(testFilePath))
		require.False(t, sysFs.IsDir(testFilePath))

		f, err := sysFs.Create(testFilePath)
		require.NoError(t, err)
		require.NotNil(t, f)
		require.True(t, sysFs.Exists(testFilePath))
		require.False(t, sysFs.IsDir(testFilePath))
		require.NoError(t, f.Close())

		fi, err := sysFs.Stat(testFilePath)
		require.NoError(t, err)
		require.NotNil(t, f)
		require.False(t, fi.IsDir())
		require.Equal(t, fi.Mode().String(), "-rw-r--r--")

		confirmedDir, fn, err := sysFs.Resolve(testFilePath)
		require.NoError(t, err)
		require.Equal(t, fn, "create.dat")
		require.Equal(t, confirmedDir, ConfirmedDir(tmpDir))

		payload, err := randomness.Bytes(32)
		require.NoError(t, err)

		require.NoError(t, sysFs.WriteFile(testFilePath, payload, 0o666))
		fileContent, err := sysFs.ReadFile(testFilePath)
		require.NoError(t, err)
		require.Equal(t, payload, fileContent)

		require.NoError(t, sysFs.Chmod(testFilePath, 0o600))

		fi2, err := sysFs.Stat(testFilePath)
		require.NoError(t, err)
		require.NotNil(t, fi2)
		require.Equal(t, fi2.Mode().String(), "-rw-------")

		targetSymlink := filepath.Join(tmpDir, "symlink")
		require.False(t, sysFs.Exists(targetSymlink))
		require.NoError(t, sysFs.Symlink(testFilePath, targetSymlink))
		fi3, err := sysFs.Stat(targetSymlink)
		require.NoError(t, err)
		require.NotNil(t, fi3)
		require.Equal(t, fi3.Mode().String(), "-rw-------")
		require.True(t, sysFs.Exists(targetSymlink))

		confirmedDir, fn, err = sysFs.Resolve(targetSymlink)
		require.NoError(t, err)
		require.Equal(t, fn, "create.dat")
		require.Equal(t, confirmedDir, ConfirmedDir(tmpDir))

		require.NoError(t, sysFs.Remove(targetSymlink))
		fi4, err := sysFs.Stat(targetSymlink)
		require.Error(t, err)
		require.Nil(t, fi4)
		require.False(t, sysFs.Exists(targetSymlink))

		targetHardlink := filepath.Join(tmpDir, "hardlink")
		require.False(t, sysFs.Exists(targetHardlink))
		require.NoError(t, sysFs.Link(testFilePath, targetHardlink))
		fi5, err := sysFs.Stat(targetHardlink)
		require.NoError(t, err)
		require.NotNil(t, fi5)
		require.Equal(t, fi5.Mode().String(), "-rw-------")
		require.True(t, sysFs.Exists(targetHardlink))

		confirmedDir, fn, err = sysFs.Resolve(targetHardlink)
		require.NoError(t, err)
		require.Equal(t, fn, "hardlink")
		require.Equal(t, confirmedDir, ConfirmedDir(tmpDir))

		require.NoError(t, sysFs.Remove(targetHardlink))
		fi6, err := sysFs.Stat(targetHardlink)
		require.Error(t, err)
		require.Nil(t, fi6)
		require.False(t, sysFs.Exists(targetHardlink))

		fo, err := sysFs.Open(testFilePath)
		require.NoError(t, err)
		require.NotNil(t, fo)

		content, err := io.ReadAll(fo)
		require.NoError(t, err)
		require.Equal(t, payload, content)

		fio, err := fo.Stat()
		require.NoError(t, err)
		require.NotNil(t, fio)
		require.Equal(t, fio.Mode().String(), "-rw-------")

		require.NoError(t, fo.Close())
	})

	t.Run("directory operations", func(t *testing.T) {
		oneDir := filepath.Join(tmpDir, "one")

		require.False(t, sysFs.Exists(oneDir))
		require.NoError(t, sysFs.Mkdir(oneDir, 0o755))
		require.True(t, sysFs.Exists(oneDir))
		require.True(t, sysFs.IsDir(oneDir))

		confirmedDir, fn, err := sysFs.Resolve(oneDir)
		require.NoError(t, err)
		require.Equal(t, fn, "")
		require.Equal(t, confirmedDir, ConfirmedDir(oneDir))

		subDirs := filepath.Join(tmpDir, "subdir", "one", "two", "three")

		require.False(t, sysFs.Exists(filepath.Join(tmpDir, "subdir")))
		require.False(t, sysFs.Exists(filepath.Join(tmpDir, "subdir", "one")))
		require.False(t, sysFs.Exists(filepath.Join(tmpDir, "subdir", "one", "two")))
		require.False(t, sysFs.Exists(subDirs))
		require.NoError(t, sysFs.MkdirAll(subDirs, 0o755))
		require.True(t, sysFs.Exists(filepath.Join(tmpDir, "subdir")))
		require.True(t, sysFs.Exists(filepath.Join(tmpDir, "subdir", "one")))
		require.True(t, sysFs.Exists(filepath.Join(tmpDir, "subdir", "one", "two")))
		require.True(t, sysFs.Exists(subDirs))

		require.NoError(t, sysFs.RemoveAll(filepath.Join(tmpDir, "subdir")))
		require.False(t, sysFs.Exists(subDirs))
		require.False(t, sysFs.Exists(filepath.Join(tmpDir, "subdir", "one", "two")))
		require.False(t, sysFs.Exists(filepath.Join(tmpDir, "subdir", "one")))
		require.False(t, sysFs.Exists(filepath.Join(tmpDir, "subdir")))

		entries, err := sysFs.Glob("*")
		require.NoError(t, err)
		require.NotEmpty(t, entries)

		entries, err = sysFs.Glob("no-match")
		require.NoError(t, err)
		require.Empty(t, entries)

		dirEntries, err := sysFs.ReadDir(subDirs)
		require.Error(t, err)
		require.Empty(t, dirEntries)

		dirEntries, err = sysFs.ReadDir(tmpDir)
		require.NoError(t, err)
		require.NotEmpty(t, dirEntries)

		var names []string
		require.NoError(t, sysFs.WalkDir(tmpDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			path = filepath.Clean(strings.TrimPrefix(path, tmpDir))

			if d.IsDir() {
				names = append(names, fmt.Sprintf("d %s", path))
			} else {
				names = append(names, fmt.Sprintf("f %s", path))
			}

			return nil
		}))
		require.Equal(t, []string{"d .", "f /create.dat", "d /one"}, names)
	})
}
