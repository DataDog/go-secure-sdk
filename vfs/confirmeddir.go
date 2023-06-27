// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ConfirmedDir is a clean, absolute, delinkified path
// that was confirmed to point to an existing directory.
type ConfirmedDir string

// NewTmpConfirmedDir returns a temporary dir, else error.
// The directory is cleaned, no symlinks, etc. so it's
// returned as a ConfirmedDir.
func NewTmpConfirmedDir() (ConfirmedDir, error) {
	n, err := os.MkdirTemp("", "dd-vfs-")
	if err != nil {
		return "", fmt.Errorf("unable to create temporary directory: %w", err)
	}

	// In MacOs `os.MkdirTemp` creates a directory
	// with root in the `/var` folder, which is in turn
	// a symlinked path to `/private/var`.
	// Function `filepath.EvalSymlinks`is used to
	// resolve the real absolute path.
	deLinked, err := filepath.EvalSymlinks(n)
	return ConfirmedDir(deLinked), err
}

// HasPrefix ensure that the given path has the confirmed directory as prefix.
func (d ConfirmedDir) HasPrefix(path ConfirmedDir) bool {
	if path.String() == string(filepath.Separator) || path == d {
		return true
	}
	return strings.HasPrefix(
		string(d),
		string(path)+string(filepath.Separator))
}

// Join the given path to the confirmed directory.
func (d ConfirmedDir) Join(path string) string {
	return filepath.Join(string(d), path)
}

func (d ConfirmedDir) String() string {
	return string(d)
}
