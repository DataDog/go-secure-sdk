// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package zip

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/go-secure-sdk/ioutil"
	"github.com/DataDog/go-secure-sdk/vfs"
)

// Extract ZIP content from the reader to the given outPath prefix.
//
// outPath must be controlled by the developer and verified before being used as
// the extraction path.
//
//nolint:gocognit,gocyclo // This function is complex by nature
func Extract(r io.ReaderAt, size uint64, outPath string, opts ...Option) error {
	// Check arguments
	if r == nil {
		return errors.New("reader must not be nil")
	}
	if outPath == "" {
		return errors.New("output path must not be blank")
	}

	// Apply default options
	dopts := &options{
		MaxArchiveSize: defaultMaxArchiveSize,
		MaxFileSize:    defaultMaxFileSize,
		MaxEntryCount:  defaultMaxEntryCount,
	}
	for _, o := range opts {
		o(dopts)
	}

	// Create chrooted filesystem
	out, err := vfs.Chroot(outPath)
	if err != nil {
		return fmt.Errorf("unable to initialize chrooted filesystem: %w", err)
	}

	// Ensure not too large archive
	if size > dopts.MaxArchiveSize {
		return fmt.Errorf("the archive is too large to be extracted: %w", ErrAbortedOperation)
	}

	// ZIP format reader
	zipReader, err := zip.NewReader(r, int64(size))
	if err != nil {
		return fmt.Errorf("unable to initialize ZIP reader: %w", err)
	}

	// Ensure not too many files
	archiveFileCount := len(zipReader.File)
	if archiveFileCount > int(dopts.MaxEntryCount) {
		return fmt.Errorf("the archive contains too many file entries: %w", ErrAbortedOperation)
	}

	symlinks := []*zip.File{}
	for _, f := range zipReader.File {
		// Clean double separators to prevent to be interpreted as UNC on windows
		origName := strings.ReplaceAll(filepath.ToSlash(f.Name), "//", "/")

		// Clean file path.
		targetPath := filepath.Clean(origName)
		if targetPath == "." {
			continue
		}

		// Check for zip-slip attacks (1st pass)
		// This is mitigated by the vfs.Chroot() call above but we still want to
		// check for the case where the chrooted filesystem is not used.
		// This is also useful to prevent the case where the chrooted filesystem is
		// bypassed or doesn't work properly.
		// It will also prevent CodeQL from reporting a potential zip-slip attack.
		if !strings.HasPrefix(filepath.Join(outPath, targetPath), filepath.Clean(outPath)+string(os.PathSeparator)) {
			return fmt.Errorf("zip entry %s is trying to escape the destination directory", f.Name)
		}

		// Determine if we need to skip the FS item
		if dopts.OverwriteFilter != nil {
			// Check existence
			tfi, err := out.Stat(targetPath)
			switch {
			case err == nil:
				// Nothing to do
			case errors.Is(err, fs.ErrNotExist):
				// Nothing to do
			default:
				return fmt.Errorf("unable to retrieve target file info: %w", err)
			}

			// Check if we have to skip the file overwrite
			if tfi != nil && dopts.OverwriteFilter(targetPath, tfi) {
				// Skip the file
				continue
			}
		}

		// Get base directory to ensure existing directory hierarchy
		baseDir := filepath.Dir(targetPath)

		// Check folder hierarchy existence.
		if !out.Exists(baseDir) {
			if err := out.MkdirAll(baseDir, 0o750); err != nil {
				return fmt.Errorf("unable to create intermediate directories for path '%s': %w", baseDir, err)
			}
		}

		// Retrieve file information
		fi := f.FileInfo()

		switch {
		case fi.IsDir():
			// ignore
		case fi.Mode()&fs.ModeSymlink != 0:
			// Add symlinks to post-processing
			symlinks = append(symlinks, f)
		case fi.Mode().IsRegular():
			// Open compressed file
			fileReader, err := f.Open()
			if err != nil {
				return fmt.Errorf("unable to open compressed file %q: %w", f.Name, err)
			}

			// Create file
			targetFile, err := out.Create(targetPath)
			if err != nil {
				return fmt.Errorf("unable to create the output file: %w", err)
			}

			// Ensure uncompressed size is not too small (header manipulation attack)
			if !dopts.DisableFileSizeCheck && f.UncompressedSize64 > dopts.MaxFileSize {
				return fmt.Errorf("file %q is too large to be extracted: %w", f.Name, ErrAbortedOperation)
			}

			// Use a buffered decompression to the file directly
			n, err := ioutil.LimitCopy(targetFile, fileReader, min(f.UncompressedSize64, dopts.MaxFileSize))
			if err != nil {
				return fmt.Errorf("unable to decompress file: %w", err)
			}
			if !dopts.DisableFileSizeCheck && n > f.UncompressedSize64 {
				return fmt.Errorf("file %q has an invalid size (expected:%d actual:%d): %w", f.Name, f.UncompressedSize64, n, ErrAbortedOperation)
			}

			// Close compressed file
			if err := fileReader.Close(); err != nil {
				return fmt.Errorf("unable to close the compressed file %q: %w", f.Name, err)
			}

			// Close the target file
			if err := targetFile.Close(); err != nil {
				return fmt.Errorf("unable to successfully close %q file: %w", targetPath, err)
			}
		}
	}

	// Post process symlinks
	for _, f := range symlinks {
		targetName := filepath.Clean(f.Name)

		// Open file
		r, err := f.Open()
		if err != nil {
			return fmt.Errorf("unable read symlink path: %w", err)
		}

		// Retrieve sumbolic name as content
		linkName, err := io.ReadAll(io.LimitReader(r, 2048))
		if err != nil {
			return fmt.Errorf("unable to drain symlink name reader: %w", err)
		}

		// Absolute or relative symlink
		var targetLinkName string
		if filepath.IsAbs(string(linkName)) {
			targetLinkName = filepath.Clean(string(linkName))
		} else {
			targetLinkName = filepath.Join(filepath.Dir(targetName), string(linkName))
		}

		// Check for zip-slip attacks (1st pass)
		// This is mitigated by the vfs.Chroot() call above but we still want to
		// check for the case where the chrooted filesystem is bypassed or doesn't
		// work properly.
		if !strings.HasPrefix(filepath.Join(outPath, targetLinkName), filepath.Clean(outPath)+string(os.PathSeparator)) {
			return fmt.Errorf("zip entry %s is trying to escape the destination directory", f.Name)
		}

		// Confirm filesystem membership
		if _, _, err := out.Resolve(targetLinkName); err != nil {
			return fmt.Errorf("unable to validate symlink target: %w", err)
		}

		// Create an absolute symlink
		if err := out.Symlink(targetLinkName, targetName); err != nil {
			return fmt.Errorf("unable to create symlink: %w", err)
		}
	}

	return nil
}
