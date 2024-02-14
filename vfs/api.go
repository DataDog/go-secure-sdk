// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"io"
	"io/fs"
	"path/filepath"
)

const (
	Separator = string(filepath.Separator)
	SelfDir   = "."
	ParentDir = ".."
	FakeRoot  = "/"
)

// File represents the file writer interface.
type File interface {
	fs.File
	io.Writer
}

// SymlinkFS extends the default filesystem abstraction to add symbolic link
// operations. (target Go 1.23)
//
// https://github.com/golang/go/issues/49580
type SymlinkFS interface {
	fs.FS

	// ReadLink returns the destination of the named symbolic link.
	ReadLink(name string) (string, error)

	// Lstat returns a FileInfo describing the file without following any
	// symbolic links.
	// If there is an error, it should be of type *PathError.
	Lstat(name string) (fs.FileInfo, error)
}

// FileSystem extends the default read-only filesystem abstraction to add write
// operations.
type FileSystem interface {
	fs.FS
	fs.StatFS
	fs.ReadDirFS
	fs.ReadFileFS
	fs.GlobFS
	SymlinkFS

	// Create a file.
	Create(name string) (File, error)
	// Mkdir creates a directory form the given path.
	Mkdir(path string, perm fs.FileMode) error
	// MkdirAll creats a directory path with all intermediary directories.
	MkdirAll(path string, perm fs.FileMode) error
	// IsDir returns true if the path is a directory.
	IsDir(path string) bool
	// Exists is true if the path exists in the filesystem.
	Exists(path string) bool
	// Chmod changes the filemode of the given path.
	Chmod(name string, mode fs.FileMode) error
	// Symlink creates a symbolink link.
	Symlink(path, name string) error
	// Link creates a hardlink.
	Link(path, name string) error
	// RemoveAll removes all path elements from the given path from the filesystem.
	RemoveAll(path string) error
	// Remove remove the given path from the filesystem.
	Remove(path string) error
	// Resolve the given path to return a real/delinked absolute path.
	Resolve(path string) (ConfirmedDir, string, error)
	// WriteFile writes given data to the given path as a file with the given filemode.
	WriteFile(path string, data []byte, perm fs.FileMode) error
	// WalkDir the filesystem form the given path.
	WalkDir(path string, walkFn fs.WalkDirFunc) error
}
