// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// OS returns a new instance of the OS filesystem.
func OS() FileSystem {
	return &osFS{}
}

// -----------------------------------------------------------------------------

type osFS struct{}

//nolint:wrapcheck // No need to wrap error
func (vfs osFS) Create(name string) (File, error) {
	if !vfs.isValidPath(name) {
		return nil, fmt.Errorf("invalid path: %s", name)
	}
	return createNewFile(name)
}

//nolint:wrapcheck // No need to wrap error
func (osFS) Mkdir(path string, perm fs.FileMode) error {
	return os.Mkdir(filepath.FromSlash(path), perm)
}

//nolint:wrapcheck // No need to wrap error
func (vfs osFS) MkdirAll(path string, perm fs.FileMode) error {
	return os.MkdirAll(filepath.FromSlash(path), perm)
}

//nolint:wrapcheck // No need to wrap error
func (vfs osFS) Remove(path string) error {
	return os.Remove(filepath.FromSlash(path))
}

//nolint:wrapcheck // No need to wrap error
func (vfs osFS) RemoveAll(path string) error {
	return os.RemoveAll(filepath.FromSlash(path))
}

//nolint:wrapcheck // No need to wrap error
func (vfs osFS) Open(name string) (fs.File, error) {
	if !vfs.isValidPath(name) {
		return nil, fmt.Errorf("invalid path: %s", name)
	}
	return os.Open(filepath.FromSlash(name))
}

// Exists returns true if os.Stat succeeds.
func (osFS) Exists(name string) bool {
	_, err := os.Stat(filepath.FromSlash(name))
	return err == nil
}

// IsDir delegates to os.Stat and FileInfo.IsDir
func (osFS) IsDir(name string) bool {
	info, err := os.Lstat(filepath.FromSlash(name))
	if err != nil {
		return false
	}

	return info.IsDir()
}

// ReadDir delegates to os.ReadDir
//
//nolint:wrapcheck // No need to wrap error
func (osFS) ReadDir(name string) ([]fs.DirEntry, error) {
	dirEntries, err := os.ReadDir(filepath.FromSlash(name))
	if err != nil {
		return nil, err
	}

	return dirEntries, nil
}

// ReadFile delegates to os.ReadFile.
//
//nolint:wrapcheck // No need to wrap error
func (osFS) ReadFile(name string) ([]byte, error) {
	content, err := os.ReadFile(filepath.FromSlash(name))
	return content, err
}

// WriteFile delegates to os.WriteFile with read/write permissions.
//
//nolint:wrapcheck // No need to wrap error
func (osFS) WriteFile(name string, c []byte, perm fs.FileMode) error {
	return os.WriteFile(filepath.FromSlash(name), c, perm)
}

// Glob returns the list of matching files
//
//nolint:wrapcheck // No need to wrap error
func (osFS) Glob(pattern string) ([]string, error) {
	allFilePaths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	return allFilePaths, nil
}

// Walk delegates to filepath.Walk.
//
//nolint:wrapcheck // No need to wrap error
func (vfs osFS) WalkDir(path string, walkFn fs.WalkDirFunc) error {
	return fs.WalkDir(vfs, filepath.FromSlash(path), walkFn)
}

//nolint:wrapcheck // No need to wrap error
func (vfs osFS) Chmod(name string, mode fs.FileMode) error {
	return os.Chmod(filepath.FromSlash(name), mode)
}

//nolint:wrapcheck // No need to wrap error
func (vfs osFS) Chown(name string, uid, gid int) error {
	return os.Chown(filepath.FromSlash(name), uid, gid)
}

//nolint:wrapcheck // No need to wrap error
func (vfs osFS) Chtimes(name string, atime, mtime time.Time) error {
	return os.Chtimes(filepath.FromSlash(name), atime, mtime)
}

//nolint:wrapcheck // No need to wrap error
func (vfs osFS) Stat(name string) (fs.FileInfo, error) {
	return os.Stat(filepath.FromSlash(name))
}

//nolint:wrapcheck // No need to wrap error
func (vfs osFS) Lstat(name string) (fs.FileInfo, error) {
	return os.Lstat(filepath.FromSlash(name))
}

//nolint:wrapcheck // No need to wrap error
func (vfs osFS) ReadLink(name string) (string, error) {
	return os.Readlink(filepath.FromSlash(name))
}

//nolint:wrapcheck // No need to wrap error
func (vfs osFS) Symlink(oldname, newname string) error {
	return os.Symlink(filepath.FromSlash(oldname), filepath.FromSlash(newname))
}

//nolint:wrapcheck // No need to wrap error
func (vfs osFS) Link(oldname, newname string) error {
	return os.Link(filepath.FromSlash(oldname), filepath.FromSlash(newname))
}

// Resolve the given path membership within the filesystem.
// If resolved the function returns :
// * a confirmedDirectory instance for a directory or a file path;
// * the filename for a file path.
func (vfs osFS) Resolve(path string) (ConfirmedDir, string, error) {
	// Ensure an absolute path
	absRoot, err := filepath.Abs(filepath.FromSlash(path))
	if err != nil {
		return "", "", fmt.Errorf("abs path error on '%s' : %v", path, err)
	}

	// Resolve the potential symlink to retrieve the real target.
	deLinked, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return "", "", fmt.Errorf("evalsymlink failure on %q : %w", absRoot, err)
	}

	// If the target is a directory, we don't need to continue.
	if vfs.IsDir(deLinked) {
		return ConfirmedDir(deLinked), "", nil
	}

	// Extract filename part from the delinked path
	d := filepath.Dir(deLinked)

	// Assertion test - ensure a directory as root of the file
	if !vfs.IsDir(d) {
		return "", "", fmt.Errorf("first part of %q is not a directory", deLinked)
	}
	// Assertion test - self reference
	if d == deLinked {
		return "", "", fmt.Errorf("d %q should be a subset of delinked", d)
	}
	// Assertion test - ensure computed filename path is the delinked path
	f := filepath.Base(deLinked)
	if filepath.Join(d, f) != deLinked {
		return "", "", fmt.Errorf("these should be equal: '%s', '%s'", filepath.Join(d, f), deLinked)
	}

	return ConfirmedDir(filepath.FromSlash(d)), f, nil
}

func (vfs osFS) isValidPath(path string) bool {
	d, f := filepath.Split(path)
	if !vfs.IsDir(d) {
		return false
	}
	if isInvalidFilename(f) {
		return false
	}
	return true
}
