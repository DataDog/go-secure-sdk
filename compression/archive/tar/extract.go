// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package tar

import (
	"archive/tar"
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

// Extract TAR content from the reader to the given outPath prefix.
//
// outPath must be controlled by the developer and verified before being used as
// the extraction path.
// The extraction process is protected against zip-slip attacks, limited in terms
// of file count, and file size.
//
//nolint:gocognit // This function is complex by nature
func Extract(r io.Reader, outPath string, opts ...Option) error {
	// Check arguments
	if r == nil {
		return errors.New("reader must not be nil")
	}
	if outPath == "" {
		return errors.New("output path must not be blank")
	}

	// Apply default options
	dopts := &options{
		MaxArchiveSize:      defaultMaxArchiveSize,
		MaxFileSize:         defaultMaxFileSize,
		MaxEntryCount:       defaultMaxEntryCount,
		MaxSymlinkRecursion: defaultMaxSymlinkRecursion,
	}
	for _, o := range opts {
		o(dopts)
	}

	// Create chrooted filesystem
	out, err := vfs.Chroot(outPath)
	if err != nil {
		return fmt.Errorf("unable to initialize chrooted filesystem: %w", err)
	}

	// TAR format reader
	tarReader := tar.NewReader(io.LimitReader(r, int64(dopts.MaxArchiveSize)))

	symlinks := []*tar.Header{}
	entryCount := uint64(0)
	for {
		// Iterate on each file entry
		hdr, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("unable to read tar entry: %w", err)
		}
		if hdr == nil {
			continue
		}

		// Retrieve fileinfo
		fi := hdr.FileInfo()

		// Skip devices nodes
		if fi.Mode()&fs.ModeDevice != 0 || fi.Mode()&fs.ModeCharDevice != 0 {
			continue
		}

		// Increment entry count used as a hard limit to prevent too large archive
		entryCount++
		if entryCount > dopts.MaxEntryCount {
			return fmt.Errorf("the archive contains too many file entries: %w", ErrAbortedOperation)
		}

		// Clean double separators to prevent to be interpreted as UNC on windows
		origName := strings.ReplaceAll(filepath.ToSlash(hdr.Name), "//", "/")

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
			return fmt.Errorf("tar entry %s is trying to escape the destination directory", hdr.Name)
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

		switch hdr.Typeflag {
		case tar.TypeDir:
			// Ignore directories
		case tar.TypeSymlink, tar.TypeLink:
			// Add symlinks to post-processing
			symlinks = append(symlinks, hdr)
		case tar.TypeReg:
			// Create file
			targetFile, err := out.Create(targetPath)
			if err != nil {
				return fmt.Errorf("unable to create the output file: %w", err)
			}

			// Use a buffered copy from the file directly
			if _, err := ioutil.LimitCopy(targetFile, tarReader, dopts.MaxFileSize); err != nil {
				return fmt.Errorf("unable to extract file: %w", err)
			}

			// Close the target file
			if err := targetFile.Close(); err != nil {
				return fmt.Errorf("unable to successfully close %q file: %w", targetPath, err)
			}

			// Update file attributes
			if err := out.Chmod(targetPath, fs.FileMode(hdr.Mode)); err != nil {
				return fmt.Errorf("unable to update file attributes: %w", err)
			}
		default:
			// ignore
		}
	}

	// Process symlinks and hardlinks
	if len(symlinks) > 0 {
		if err := processLinks(0, dopts.MaxSymlinkRecursion, outPath, out, symlinks); err != nil {
			return fmt.Errorf("unable to process symlinks: %w", err)
		}
	}

	return nil
}

func processLinks(level, maxRecursionDepth uint64, outPath string, out vfs.FileSystem, symlinks []*tar.Header) error {
	// Check recursion level
	if level > maxRecursionDepth {
		return fmt.Errorf("maximum symlink recursion level reached (%d): %w", level, ErrAbortedOperation)
	}
	if len(symlinks) == 0 {
		// Fast path
		return nil
	}

	// Prepare next pass
	next := []*tar.Header{}

	// Post process symlinks
	for _, hdr := range symlinks {
		if hdr == nil {
			continue
		}

		targetName := filepath.Clean(hdr.Name)

		// Absolute or relative symlink
		var targetLinkName string
		if filepath.IsAbs(hdr.Linkname) {
			targetLinkName = filepath.Clean(hdr.Linkname)
		} else {
			//nolint:gosec // Path traversal is mitigated by the filesystem abstraction
			targetLinkName = filepath.Join(filepath.Dir(targetName), hdr.Linkname)
		}

		// Check for zip-slip attacks (1st pass)
		// This is mitigated by the vfs.Chroot() call above but we still want to
		// check for the case where the chrooted filesystem is bypassed or doesn't
		// work properly.
		if !strings.HasPrefix(filepath.Join(outPath, targetLinkName), filepath.Clean(outPath)+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry %s is trying to escape the destination directory", hdr.Name)
		}

		// Check if the target link already exists, if not, add to next pass
		if !out.Exists(targetLinkName) {
			// Add to next pass
			next = append(next, hdr)
			continue
		}

		// Confirm filesystem membership
		if _, _, err := out.Resolve(targetLinkName); err != nil {
			return fmt.Errorf("unable to validate symlink target: %w", err)
		}

		switch hdr.Typeflag {
		case tar.TypeLink:
			// Create an absolute hardlink
			if err := out.Link(targetLinkName, targetName); err != nil {
				return fmt.Errorf("unable to create hardlink: %w", err)
			}
		case tar.TypeSymlink:
			// Create an absolute symlink
			if err := out.Symlink(targetLinkName, targetName); err != nil {
				return fmt.Errorf("unable to create symlink: %w", err)
			}
		}
	}

	// Process next pass
	if len(next) > 0 {
		return processLinks(level+1, maxRecursionDepth, outPath, out, next)
	}

	return nil
}
