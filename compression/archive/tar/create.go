// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package tar

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/DataDog/go-secure-sdk/ioutil"
	"github.com/DataDog/go-secure-sdk/log"
)

// Create an archive from given options to the given writer.
//
//nolint:gocognit
func Create(fileSystem fs.FS, w io.Writer, opts ...Option) error {
	// Check arguments
	if fileSystem == nil {
		return errors.New("fileSystem is nil")
	}
	if w == nil {
		return errors.New("output writer is nil")
	}

	// Apply default options
	dopts := &options{
		MaxFileSize:   defaultMaxFileSize,
		MaxEntryCount: defaultMaxEntryCount,
	}
	for _, o := range opts {
		o(dopts)
	}

	// Ensure the root actually exists before trying to tar it
	rootFi, err := fs.Stat(fileSystem, ".")
	if err != nil {
		return fmt.Errorf("unable to tar files: %w", err)
	}
	if !rootFi.IsDir() {
		return errors.New("root path must be a directory")
	}

	// Create writer chain.
	tw := tar.NewWriter(w)

	archivedItems := uint64(0)

	// walk through every file in the folder
	if errWalk := fs.WalkDir(fileSystem, ".", func(file string, dirEntry fs.DirEntry, errIn error) error {
		// return on any error
		if errIn != nil {
			return errIn
		}

		// ignore invalid file path
		if !fs.ValidPath(file) {
			return nil
		}

		// Get FileInfo
		fi, err := dirEntry.Info()
		if err != nil {
			return fmt.Errorf("unable to retrieve fileInfo for %q: %w", file, err)
		}

		// Ignore invalid files
		if !fi.IsDir() && !fi.Mode().IsRegular() {
			return nil
		}

		// Check file size
		if fi.Size() > int64(dopts.MaxFileSize) {
			return fmt.Errorf("unable to add entry %q: data above the threshold", file)
		}

		// Check item inclusion
		if dopts.IncludeFilter != nil {
			if !dopts.IncludeFilter(file, fi) {
				// Exclude this item from the archive
				return nil
			}
		}

		// Check item exclusion
		if dopts.ExcludeFilter != nil {
			if dopts.ExcludeFilter(file, fi) {
				// Exclude this item from the archive
				return nil
			}
		}

		// Skip directory creation if not enabled.
		if !dopts.AddEmptyDirectories && fi.IsDir() {
			return nil
		}

		// generate tar header
		header, err := tar.FileInfoHeader(fi, file)
		if err != nil {
			return fmt.Errorf("unable to create TAR File header: %w", err)
		}

		// Require header modifications
		if dopts.HeaderRewritter != nil {
			header = dopts.HeaderRewritter(header)
			if header == nil {
				return errors.New("tar header rewriting error, the returned header is nil")
			}
		}

		// write header
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("unable to write TAR header: %w", err)
		}

		// if not a dir, write file content
		if !fi.IsDir() {
			data, err := fileSystem.Open(file)
			if err != nil {
				return fmt.Errorf("unable to open source file %q: %w", file, err)
			}
			defer func(closer io.Closer) {
				if err := closer.Close(); err != nil {
					log.Error(err).Message("unable to close source file")
				}
			}(data)

			if _, err := ioutil.LimitCopy(tw, data, dopts.MaxFileSize); err != nil {
				return fmt.Errorf("unable to copy source file content: %w", err)
			}
		}

		// Increase archived item count
		archivedItems++

		// Check maximum archived count limit
		if archivedItems > dopts.MaxEntryCount {
			return fmt.Errorf("the archive contains more entries than the allowed limit: %w", ErrAbortedOperation)
		}

		// No error
		return nil
	}); errWalk != nil {
		return fmt.Errorf("fail to walk folders for archive compression: %w", errWalk)
	}

	// Ensure something archived
	if archivedItems == 0 {
		return ErrNothingArchived
	}

	// Close the TR writer to ensure trailing bits to be synced
	if err := tw.Close(); err != nil {
		return fmt.Errorf("unable to successfully close the TAR writer: %w", err)
	}

	// No error
	return nil
}
