// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package atomic

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/DataDog/go-secure-sdk/log"
)

// WriteFile atomically replace the file content of the filename target by the
// reader content. If an error occurs the temporary file is deleted and nothing
// is touched.
func WriteFile(filename string, r io.Reader) (err error) {
	// Extract file and directory
	dir, file := filepath.Split(filename)

	// Ensure a clean directory
	dir = filepath.Clean(dir)

	// Create a temporary file
	f, err := os.CreateTemp(dir, file)
	if err != nil {
		return fmt.Errorf("unable to create the temporary file: %w", err)
	}
	defer func() {
		// Ensure that the temporary file is removed in all cases.
		if err := os.Remove(f.Name()); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				log.Error(err).Messagef("unable to remove temporary file %q", f.Name())
			}
		}
	}()
	defer func(closer io.Closer) {
		// Close the temporary file
		if err := closer.Close(); err != nil {
			if !errors.Is(err, fs.ErrClosed) {
				log.Error(err).Message("unable to successfully close the file handler")
			}
		}
	}(f)

	// Use a buffered IO Reader to reduce write syscalls
	bio := bufio.NewWriter(f)

	// Copy the file content
	if _, err := io.Copy(bio, r); err != nil {
		return fmt.Errorf("unable to copy the reader content to the temporary file: %w", err)
	}

	// Flush the fuffered writer to ensure that there is no dangling data.
	if err := bio.Flush(); err != nil {
		return fmt.Errorf("unable ot flush to buffered writer: %w", err)
	}

	// Ensure that the input file is synced to disk.
	if err := f.Sync(); err != nil {
		return fmt.Errorf("unable to sync file content: %w", err)
	}

	// Explicitly close the temporary file
	if err = f.Close(); err != nil {
		return fmt.Errorf("unable to close the temporary file: %w", err)
	}

	// Ensure real temporary file (MacOS has symlinks to temporary files)
	tmpFilename, err := filepath.EvalSymlinks(f.Name())
	if err != nil {
		return fmt.Errorf("unable to evaluate %q symlink: %w", f.Name(), err)
	}

	// Ensure directory to be synced too
	if err := syncDir(filepath.Dir(tmpFilename)); err != nil {
		return fmt.Errorf("unable to sync directory %q: %w", dir, err)
	}

	// Retrieve temporary file information
	tmpFi, err := os.Stat(tmpFilename)
	if err != nil {
		return fmt.Errorf("unable to retrieve temporary %q file information: %w", f.Name(), err)
	}

	// Retrieve target filename fileinfo
	fi, err := os.Stat(filename)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Ignore, the file doesn't exist yet.
	case err != nil:
		return fmt.Errorf("unable to retrieve target %q file information: %w", filename, err)
	default:
		// Ensure real temporary file (MacOS has symlinks to temporary files)
		filename, err = filepath.EvalSymlinks(filename)
		if err != nil {
			return fmt.Errorf("unable to evaluate %q symlink: %w", f.Name(), err)
		}

		// Ensure similar file modes
		if tmpFi.Mode() != fi.Mode() {
			if err := os.Chmod(tmpFilename, fi.Mode()); err != nil {
				return fmt.Errorf("unable to apply file modes to temporary file %q: %q", f.Name(), err)
			}
		}
	}

	// Move the temporary file to the target file
	if err := os.Rename(tmpFilename, filename); err != nil {
		return fmt.Errorf("unable to replace the target file %q by the temporary one: %w", filename, err)
	}

	return nil
}

// -----------------------------------------------------------------------------

// syncDir ensure that the directory handle is Synced on disk by explicitly calling
// fsync to the directory handle.
func syncDir(dir string) error {
	// Open the directory
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("unable to open the target directory %q: %w", dir, err)
	}

	// Retrieve file information
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("unable retrieve file information for %q: %w", dir, err)
	}

	// Ensure the target is a directory
	if !fi.IsDir() {
		return fmt.Errorf("unable to apply directory sync on a file")
	}

	// Sync to disk
	if err := f.Sync(); err != nil {
		return fmt.Errorf("unable sync directory %q: %w", dir, err)
	}

	// Close the directory handle
	if err := f.Close(); err != nil {
		return fmt.Errorf("unable to close the directory handle for %q: %w", dir, err)
	}

	return nil
}
