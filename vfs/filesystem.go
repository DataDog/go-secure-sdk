package vfs

import (
	"errors"
	"fmt"
)

// ConfirmDir returns an error if the user-specified path is not an existing
// directory on root.
// Otherwise, ConfirmDir returns path, which can be relative, as a ConfirmedDir
// and all that implies.
func ConfirmDir(root FileSystem, path string) (ConfirmedDir, error) {
	// Check argument
	if root == nil {
		return "", errors.New("root filesystem must not be nil")
	}
	if path == "" {
		return "", errors.New("directory path cannot be empty")
	}

	d, f, err := root.Resolve(path)
	if err != nil {
		return "", fmt.Errorf("not a valid directory: %w", err)
	}
	if f != "" {
		return "", fmt.Errorf("file %q is not a directory", f)
	}

	return d, nil
}

// ChrootFS creates a chrooted filesystem instance from the given filesystem and
// the path.
// The path must be a directory part of the given root filesystem to be used.
func ChrootFS(root FileSystem, path string) (FileSystem, error) {
	// Check argument
	if root == nil {
		return nil, errors.New("root filesystem must not be nil")
	}

	// Try to chroot to the given root path
	chroot, f, err := root.Resolve(path)
	if err != nil {
		return nil, fmt.Errorf("unable to check root %q as a valid chroot value: %w", path, err)
	}
	if f != "" {
		return nil, errors.New("unable to change root to a file")
	}

	return chrootFS{
		unsafeFS: root,
		root:     chroot,
	}, nil
}
