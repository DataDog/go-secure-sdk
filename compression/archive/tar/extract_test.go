// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package tar

import (
	"archive/tar"
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/compression/archive/tar/builder"
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
			err := Extract(f, t.TempDir(),
				WithRestoreTimes(true),
			)
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

func fingerprint(t *testing.T, root vfs.FileSystem) string {
	t.Helper()

	var out strings.Builder
	err := fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip the root
		if path == "." {
			return nil
		}
		if d.IsDir() {
			out.WriteString(fmt.Sprintf("d:%s\n", path))
			return nil
		}

		// Content content hash
		h, err := hashutil.FileHash(root, path, crypto.SHA256)
		require.NoError(t, err)

		// Get file info
		fi, err := root.Lstat(path)
		require.NoError(t, err)

		if fi.Mode()&os.ModeSymlink != 0 {
			out.WriteString(fmt.Sprintf("l:%s:%s\n", path, fi.Name()))
		} else {
			out.WriteString(fmt.Sprintf("f:%s:%d:%s\n", path, fi.Size(), hex.EncodeToString(h)))
		}

		return nil
	})
	require.NoError(t, err)

	return out.String()
}

func TestExtract_Archive_SizeLimiter(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	b, err := builder.New(out).With(
		builder.File("file.txt", strings.NewReader("hello, world")),
		builder.File("file2.txt", strings.NewReader("hello, world")),
		builder.File("file3.txt", strings.NewReader("hello, world")),
	)
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Close())

	tmpDir := t.TempDir()
	require.Error(t, Extract(out, tmpDir, WithMaxArchiveSize(2)))
}

func TestExtract_Archive_CountLimiter(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	b, err := builder.New(out).With(
		builder.File("file.txt", strings.NewReader("hello, world")),
		builder.File("file2.txt", strings.NewReader("hello, world")),
		builder.File("file3.txt", strings.NewReader("hello, world")),
	)
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Close())

	tmpDir := t.TempDir()
	require.Error(t, Extract(out, tmpDir, WithMaxEntryCount(2)))

	// Create a new file system
	root, err := vfs.Chroot(tmpDir)
	require.NoError(t, err)

	fgr := fingerprint(t, root)
	require.Equal(t, "f:file.txt:12:09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b\nf:file2.txt:12:09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b\n", fgr)
}

func TestExtract_Archive_ItemSizeLimiter(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	b, err := builder.New(out).With(
		builder.File("file.txt", strings.NewReader("hello, world")),
		builder.File("file2.txt", strings.NewReader("hello, world")),
		builder.File("file3.txt", bytes.NewReader(make([]byte, 1<<20))),
	)
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Close())

	tmpDir := t.TempDir()
	require.Error(t, Extract(out, tmpDir, WithMaxFileSize(16)))

	// Create a new file system
	root, err := vfs.Chroot(tmpDir)
	require.NoError(t, err)

	fgr := fingerprint(t, root)
	require.Equal(t, "f:file.txt:12:09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b\nf:file2.txt:12:09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b\n", fgr)
}

func TestExtract_Archive_With_Device(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	b, err := builder.New(out).With(
		builder.File("usb0", &bytes.Buffer{}, builder.WithTypeflag(tar.TypeBlock)),
		builder.File("file.txt", strings.NewReader("hello, world")),
	)
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Close())

	tmpDir := t.TempDir()
	require.NoError(t, Extract(out, tmpDir))

	// Create a new file system
	root, err := vfs.Chroot(tmpDir)
	require.NoError(t, err)

	// The device file should not be extracted
	require.False(t, root.Exists("usb0"))

	// Check the file
	data, err := root.ReadFile("file.txt")
	require.NoError(t, err)
	require.Equal(t, "hello, world", string(data))

	fgr := fingerprint(t, root)
	require.Equal(t, "f:file.txt:12:09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b\n", fgr)
}

func TestExtract_Archive_With_PathTraversal(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	b, err := builder.New(out).With(
		builder.File("../file.txt", strings.NewReader("hello, world")),
	)
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Close())

	tmpDir := t.TempDir()
	require.Error(t, Extract(out, tmpDir))
}

func TestExtract_LinkSupport_ErrorOnLoop(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	b, err := builder.New(out).With(
		builder.Symlink("zero", "one"),
		builder.Symlink("one", "two"),
		builder.Symlink("two", "zero"),
	)
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Close())

	tmpDir := t.TempDir()
	require.Error(t, Extract(out, tmpDir))
}

func TestExtract_Empty(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	b, err := builder.New(out).With()
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Close())

	tmpDir := t.TempDir()
	require.NoError(t, Extract(out, tmpDir))

	// Create a new file system
	root, err := vfs.Chroot(tmpDir)
	require.NoError(t, err)

	fgr := fingerprint(t, root)
	require.Equal(t, "", fgr)
}

func TestExtract_LinkSupport(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	b, err := builder.New(out).With(
		builder.File("file.txt", strings.NewReader("hello, world")),
		builder.Symlink("symlink", "./file.txt"),
	)
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Close())

	tmpDir := t.TempDir()
	require.NoError(t, Extract(out, tmpDir))

	// Create a new file system
	root, err := vfs.Chroot(tmpDir)
	require.NoError(t, err)

	// Check the symlink
	fi, err := root.Lstat("symlink")
	require.NoError(t, err)
	require.True(t, fi.Mode()&os.ModeSymlink != 0)

	// Check the file
	data, err := root.ReadFile("symlink")
	require.NoError(t, err)
	require.Equal(t, "hello, world", string(data))

	fgr := fingerprint(t, root)
	require.Equal(t, "f:file.txt:12:09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b\nl:symlink:symlink\n", fgr)
}

func TestExtract_HardlinkSupport(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	b, err := builder.New(out).With(
		builder.File("file.txt", strings.NewReader("hello, world")),
		builder.Hardlink("hardlink", "./file.txt"),
	)
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Close())

	tmpDir := t.TempDir()
	require.NoError(t, Extract(out, tmpDir))

	// Create a new file system
	root, err := vfs.Chroot(tmpDir)
	require.NoError(t, err)

	// Check the symlink
	fi, err := root.Lstat("hardlink")
	require.NoError(t, err)
	require.True(t, fi.Mode()&os.ModeSymlink == 0)

	// Check the file
	data, err := root.ReadFile("hardlink")
	require.NoError(t, err)
	require.Equal(t, "hello, world", string(data))

	fgr := fingerprint(t, root)
	require.Equal(t, "f:file.txt:12:09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b\nf:hardlink:12:09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b\n", fgr)
}

func TestExtract_WithRestoreTimes(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	b, err := builder.New(out).With(
		builder.File("file.txt", strings.NewReader("hello, world")),
	)
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Close())

	tmpDir := t.TempDir()
	require.NoError(t, Extract(out, tmpDir, WithRestoreTimes(true)))

	// Create a new file system
	root, err := vfs.Chroot(tmpDir)
	require.NoError(t, err)

	// Check the file
	fi, err := root.Lstat("file.txt")
	require.NoError(t, err)
	require.NotZero(t, fi.ModTime())
}

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

func TestExtract_WithRestoreMode(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	b, err := builder.New(out).With(
		builder.File("file.txt", strings.NewReader("hello, world"),
			builder.WithMode(0o400),
		),
	)
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Close())

	tmpDir := t.TempDir()
	require.NoError(t, Extract(out, tmpDir))

	// Create a new file system
	root, err := vfs.Chroot(tmpDir)
	require.NoError(t, err)

	// Check the file
	fi, err := root.Lstat("file.txt")
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o400), fi.Mode())
}
