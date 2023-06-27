// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
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
)

// File represents the file writer interface.
type File interface {
	fs.File
	io.Writer
}

// FileSystem extends the default read-only filesystem abstraction to add write
// operations.
type FileSystem interface {
	fs.FS
	fs.StatFS
	fs.ReadDirFS
	fs.ReadFileFS
	fs.GlobFS

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
	// Chmod changes the filemode of the gievn path.
	Chmod(name string, mode fs.FileMode) error
	// Symlink creates a symbolink link.
	Symlink(name, target string) error
	// Link creates a hardlink.
	Link(path, name string) error
	// RemoveAll removes all path elements from the given path from the filesystem.
	RemoveAll(path string) error
	// Remove remove the given path from the filesystem.
	Remove(path string) error
	// Resolve the given path to reutrn a real/delinked absolute path.
	Resolve(path string) (ConfirmedDir, string, error)
	// WriteFile writes given data to the given path as a file with the given filemode.
	WriteFile(path string, data []byte, perm fs.FileMode) error
	// WalkDir the filesystem form the given path.
	WalkDir(path string, walkFn fs.WalkDirFunc) error
}
