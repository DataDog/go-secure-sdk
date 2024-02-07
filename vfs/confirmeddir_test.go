package vfs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJoin(t *testing.T) {
	t.Parallel()

	// Build filesystem instance
	sysFs, err := Chroot(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, sysFs.Mkdir("/dir1", 0o755))

	d, f, err := sysFs.Resolve("/dir1")
	require.NoError(t, err)
	require.Empty(t, f)
	require.Equal(t, d.Join("subdir"), "/dir1/subdir")
}

func TestHasPrefix_Slash(t *testing.T) {
	t.Parallel()

	// Build filesystem instance
	sysFs, err := Chroot(t.TempDir())
	require.NoError(t, err)

	d, f, err := sysFs.Resolve("/")
	require.NoError(t, err)
	require.Empty(t, f)
	require.False(t, d.HasPrefix("/nope"))
	require.True(t, d.HasPrefix("/"))
}

func TestHasPrefix_SlashDir(t *testing.T) {
	t.Parallel()

	// Build filesystem instance
	sysFs, err := Chroot(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, sysFs.Mkdir("/dir1", 0o755))

	d, _, err := sysFs.Resolve("/dir1")
	require.NoError(t, err)
	require.False(t, d.HasPrefix("/dir"))
	require.False(t, d.HasPrefix("/did"))
	require.True(t, d.HasPrefix("/dir1"))
}

func TestHasPrefix_SlashDirOneSubDir(t *testing.T) {
	t.Parallel()

	// Build filesystem instance
	sysFs, err := Chroot(t.TempDir())
	require.NoError(t, err)

	err = sysFs.MkdirAll("/dir1/subdir", 0o755)
	require.NoError(t, err)

	d, _, err := sysFs.Resolve("/dir1/subdir")
	require.NoError(t, err)
	require.False(t, d.HasPrefix("/dir"))
	require.False(t, d.HasPrefix("/dir1subdir"))
	require.True(t, d.HasPrefix("/dir1/subdir"))
	require.True(t, d.HasPrefix("/dir1"))
	require.True(t, d.HasPrefix("/"))
}

func TestNewTempConfirmDir(t *testing.T) {
	t.Parallel()

	tmp, err := NewTmpConfirmedDir()
	require.NoError(t, err)
	defer os.RemoveAll(string(tmp))

	delinked, err := filepath.EvalSymlinks(string(tmp))
	require.NoError(t, err)
	require.Equal(t, tmp.String(), delinked)
}
