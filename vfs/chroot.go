// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// Chroot returns a chrooted filesystem assuming an OS base filesystem as root
// filesystem.
func Chroot(root string) (FileSystem, error) {
	return ChrootFS(OS(), root)
}

// -----------------------------------------------------------------------------

type chrootFS struct {
	root     ConfirmedDir
	unsafeFS FileSystem
}

// ConstraintError records an error and the operation and file that
// violated it.
type ConstraintError struct {
	Op   string
	Path string
	Err  error
}

// Error returns the formatted error string for the ConstraintError.
func (e *ConstraintError) Error() string {
	return "fs-security-constraint " + e.Op + " " + e.Path + ": " + e.Err.Error()
}

// Unwrap implements error unwrapping.
func (e *ConstraintError) Unwrap() error { return e.Err }

// Create delegates to the embedded unsafe FS after having confirmed the path
// to be inside root. If the provided path violates this constraint, an error
// of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) Create(path string) (File, error) {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return nil, &ConstraintError{Op: "create", Path: path, Err: err}
	}

	return vfs.unsafeFS.Create(path)
}

// Mkdir delegates to the embedded unsafe FS after having confirmed the path
// to be inside root. If the provided path violates this constraint, an error
// of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) Mkdir(path string, perm fs.FileMode) error {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return &ConstraintError{Op: "mkdir", Path: path, Err: err}
	}

	return vfs.unsafeFS.Mkdir(path, perm)
}

// MkdirAll delegates to the embedded unsafe FS after having confirmed the path
// to be inside root. If the provided path violates this constraint, an error
// type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) MkdirAll(path string, perm fs.FileMode) error {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return &ConstraintError{Op: "mkdir", Path: path, Err: err}
	}

	return vfs.unsafeFS.MkdirAll(path, perm)
}

// Remove delegates to the embedded unsafe FS after having confirmed the
// path to be inside root. If the provided path violates this constraint, an
// error of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) Remove(path string) error {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return &ConstraintError{Op: "remove", Path: path, Err: err}
	}

	return vfs.unsafeFS.Remove(path)
}

// RemoveAll delegates to the embedded unsafe FS after having confirmed the
// path to be inside root. If the provided path violates this constraint, an
// error of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) RemoveAll(path string) error {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return &ConstraintError{Op: "removeAll", Path: path, Err: err}
	}

	return vfs.unsafeFS.RemoveAll(path)
}

// Open delegates to the embedded unsafe FS after having confirmed the path
// to be inside root. If the provided path violates this constraint, an error
// of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) Open(path string) (fs.File, error) {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return nil, &ConstraintError{Op: "open", Path: path, Err: err}
	}

	return vfs.unsafeFS.Open(path)
}

// Stat delegates to the embedded unsafe FS after having confirmed the path
// to be inside root. If the provided path violates this constraint, an error
// of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) Stat(path string) (fs.FileInfo, error) {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return nil, &ConstraintError{Op: "stat", Path: path, Err: err}
	}

	return fs.Stat(vfs.unsafeFS, path)
}

// IsDir delegates to the embedded unsafe FS after having confirmed the path
// to be inside root. If the provided path violates this constraint, it returns
// false.
func (vfs chrootFS) IsDir(path string) bool {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return false
	}

	return vfs.unsafeFS.IsDir(path)
}

// ReadDir delegates to the embedded unsafe FS after having confirmed the path
// to be inside root. If the provided path violates this constraint, an error
// of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) ReadDir(path string) ([]fs.DirEntry, error) {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return nil, &ConstraintError{Op: "open", Path: path, Err: err}
	}

	return fs.ReadDir(vfs.unsafeFS, path)
}

// Resolve delegates to the embedded unsafe FS, but confirms the returned
// result to be within root. If the results violates this constraint, an error
// of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) Resolve(path string) (ConfirmedDir, string, error) {
	// Apply root prefix
	path = vfs.root.Join(path)

	d, f, err := vfs.unsafeFS.Resolve(path)
	if err != nil {
		return d, f, err
	}
	if !d.HasPrefix(vfs.root) {
		return "", "", &ConstraintError{Op: "abs", Path: path, Err: rootConstraintErr(path, vfs.root.String())}
	}

	// Resolve should return an absolute path
	newPath := filepath.Clean(strings.TrimPrefix(d.String(), vfs.root.String()))
	if newPath == SelfDir {
		return ConfirmedDir(FakeRoot), f, err
	}

	return ConfirmedDir(filepath.ToSlash(newPath)), f, err
}

// Exists delegates to the embedded unsafe FS after having confirmed the path
// to be inside root. If the provided path violates this constraint, it returns
// false.
func (vfs chrootFS) Exists(path string) bool {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return false
	}

	return vfs.unsafeFS.Exists(path)
}

// Glob delegates to the embedded unsafe FS, but filters the returned paths to
// only include items inside root.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) Glob(pattern string) ([]string, error) {
	paths, err := fs.Glob(vfs.unsafeFS, vfs.root.Join(pattern))
	if err != nil {
		return nil, err
	}
	var securePaths []string
	for _, p := range paths {
		if err := isSecurePath(vfs.unsafeFS, vfs.root, p); err == nil {
			securePaths = append(securePaths, p)
		}
	}

	return securePaths, err
}

// ReadFile delegates to the embedded unsafe FS after having confirmed the path
// to be inside root. If the provided path violates this constraint, an error
// of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) ReadFile(path string) ([]byte, error) {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return nil, &ConstraintError{Op: "read", Path: path, Err: err}
	}

	return fs.ReadFile(vfs.unsafeFS, path)
}

// WriteFile delegates to the embedded unsafe FS after having confirmed the
// path to be inside root. If the provided path violates this constraint, an
// error of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) WriteFile(path string, data []byte, perm fs.FileMode) error {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return &ConstraintError{Op: "writeFile", Path: path, Err: err}
	}

	return vfs.unsafeFS.WriteFile(path, data, perm)
}

// WalkDir delegates to the embedded unsafe FS, wrapping walkFn in a callback which
// confirms the path to be inside root. If the path violates this constraint,
// an error of type ConstraintError is returned and walkFn is not called.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) WalkDir(path string, walkFn fs.WalkDirFunc) error {
	// Apply root prefix
	path = vfs.root.Join(path)

	wrapWalkFn := func(path string, info fs.DirEntry, err error) error {
		if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
			return &ConstraintError{Op: "walk", Path: path, Err: err}
		}
		return walkFn(path, info, err)
	}

	return fs.WalkDir(vfs.unsafeFS, path, wrapWalkFn)
}

// Chmod delegates to the embedded unsafe FS after having confirmed the path
// to be inside root. If the provided path violates this constraint, an error
// of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) Chmod(path string, mode fs.FileMode) error {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return &ConstraintError{Op: "chmod", Path: path, Err: err}
	}

	return vfs.unsafeFS.Chmod(path, mode)
}

// Symlink delegates to the embedded unsafe FS after having confirmed the path
// to be inside root. If the provided path violates this constraint, an error
// of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) Symlink(sourcePath, targetName string) error {
	// Apply root prefix
	sourcePath = vfs.root.Join(sourcePath)
	targetName = vfs.root.Join(targetName)

	// Symlink should be relative to the new path when used in the chroot
	rel, err := filepath.Rel(filepath.Dir(targetName), sourcePath)
	if err != nil {
		return fmt.Errorf("symlink path %q is not relative to %q: %w", sourcePath, targetName, err)
	}

	// Ensure the symlink is secure
	if err := isSecurePath(vfs.unsafeFS, vfs.root, sourcePath); err != nil {
		return &ConstraintError{Op: "symlink", Path: sourcePath, Err: err}
	}
	if err := isSecurePath(vfs.unsafeFS, vfs.root, targetName); err != nil {
		return &ConstraintError{Op: "symlink", Path: targetName, Err: err}
	}

	return vfs.unsafeFS.Symlink(rel, targetName)
}

// Link delegates to the embedded unsafe FS after having confirmed the path
// to be inside root. If the provided path violates this constraint, an error
// of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) Link(oldpath, newpath string) error {
	// Apply root prefix
	oldpath = vfs.root.Join(oldpath)
	newpath = vfs.root.Join(newpath)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, oldpath); err != nil {
		return &ConstraintError{Op: "link", Path: oldpath, Err: err}
	}
	if err := isSecurePath(vfs.unsafeFS, vfs.root, newpath); err != nil {
		return &ConstraintError{Op: "link", Path: newpath, Err: err}
	}

	return vfs.unsafeFS.Link(oldpath, newpath)
}

// Lstat delegates to the embedded unsafe FS after having confirmed the path
// to be inside root. If the provided path violates this constraint, an error
// of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) Lstat(path string) (fs.FileInfo, error) {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return nil, &ConstraintError{Op: "lstat", Path: path, Err: err}
	}

	return vfs.unsafeFS.Lstat(path)
}

// ReadLink delegates to the embedded unsafe FS after having confirmed the path
// to be inside root. If the provided path violates this constraint, an error
// of type ConstraintError is returned.
//
//nolint:wrapcheck // No need to wrap error
func (vfs chrootFS) ReadLink(path string) (string, error) {
	// Apply root prefix
	path = vfs.root.Join(path)

	if err := isSecurePath(vfs.unsafeFS, vfs.root, path); err != nil {
		return "", &ConstraintError{Op: "readlink", Path: path, Err: err}
	}

	return vfs.unsafeFS.ReadLink(path)
}

// -----------------------------------------------------------------------------

// isSecurePath confirms the given path is inside root using the provided file
// system. At present, it assumes the file system implementation to be on disk
// and makes use of filepath.EvalSymlinks.
func isSecurePath(vfs FileSystem, root ConfirmedDir, path string) error {
	// Ensure absolute path
	absRoot, err := filepath.Abs(filepath.FromSlash(path))
	if err != nil {
		return fmt.Errorf("abs path error on '%s': %v", path, err)
	}

	d := ConfirmedDir(absRoot)
	if vfs.Exists(absRoot) {
		evaluated, err := filepath.EvalSymlinks(absRoot)
		if err != nil {
			return fmt.Errorf("evalsymlink failure on '%s': %w", path, err)
		}
		evaluatedDir := evaluated
		if !vfs.IsDir(evaluatedDir) {
			evaluatedDir = filepath.Dir(evaluatedDir)
		}
		d = ConfirmedDir(evaluatedDir)
	}
	if !d.HasPrefix(root) {
		return rootConstraintErr(path, root.String())
	}

	return nil
}

func rootConstraintErr(path, root string) error {
	return fmt.Errorf("path %q is not in or below %q", path, root)
}
