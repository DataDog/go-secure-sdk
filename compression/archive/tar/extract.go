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
//nolint:gocognit,gocyclo // This function is complex by nature
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

	// Prevent integer overflow when converting MaxArchiveSize to int64
	if dopts.MaxArchiveSize > ^uint64(0)>>1 {
		return fmt.Errorf("archive size limit too large: %d", dopts.MaxArchiveSize)
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

		// Check existence
		if fi, err := out.Lstat(targetPath); err == nil {
			// Check if the file should be overwritten
			if dopts.OverwriteFilter != nil && dopts.OverwriteFilter(targetPath, fi) {
				continue
			}

			// Remove existing file
			if !(fi.IsDir() && hdr.Typeflag == tar.TypeDir) {
				if err := out.RemoveAll(targetPath); err != nil {
					return fmt.Errorf("unable to remove existing file %q: %w", targetPath, err)
				}
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
				// Close the target file
				if err := targetFile.Close(); err != nil {
					return fmt.Errorf("unable to successfully close %q file: %w", targetPath, err)
				}
				// Remove the file
				if err := out.RemoveAll(targetPath); err != nil {
					return fmt.Errorf("unable to remove file %q: %w", targetPath, err)
				}
				return fmt.Errorf("unable to extract file: %w", err)
			}

			// Close the target file
			if err := targetFile.Close(); err != nil {
				return fmt.Errorf("unable to successfully close %q file: %w", targetPath, err)
			}

			// Prevent integer overflow when converting Mode to fs.FileMode
			if hdr.Mode > int64(^fs.FileMode(0)) {
				return fmt.Errorf("file mode too large: %d", hdr.Mode)
			}

			// Update file attributes
			//nolint:gosec // hdr.Mode is checked before being converted
			if err := out.Chmod(targetPath, fs.FileMode(hdr.Mode)); err != nil {
				return fmt.Errorf("unable to update file attributes: %w", err)
			}

			if dopts.RestoreTimes {
				// Update file timestamps
				if err := out.Chtimes(targetPath, hdr.AccessTime, hdr.ModTime); err != nil {
					return fmt.Errorf("unable to update file timestamps %q: %w", targetPath, err)
				}
			}

			//nolint:nestif // This has to adapt to the number of options
			if dopts.RestoreOwner {
				// Map UID/GID if needed
				uid, gid := hdr.Uid, hdr.Gid
				if dopts.UIDGIDMapper != nil {
					uid, gid, err = dopts.UIDGIDMapper(hdr.Uid, hdr.Gid)
					if err != nil {
						return fmt.Errorf("unable to map UID/GID on file %q: %w", targetPath, err)
					}
					if uid < 0 || gid < 0 {
						return fmt.Errorf("invalid UID/GID mapping on file %q: %w", targetPath, ErrAbortedOperation)
					}
				}

				// Update file owner
				if err := out.Chown(targetPath, uid, gid); err != nil {
					return fmt.Errorf("unable to update file owner on %q: %w", targetPath, err)
				}
			}
		default:
			// ignore
		}
	}

	// Process symlinks and hardlinks
	if len(symlinks) > 0 {
		if err := processLinks(0, dopts.MaxSymlinkRecursion, outPath, out, symlinks); err != nil {
			return fmt.Errorf("unable to process links: %w", err)
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
			if filepath.Dir(hdr.Linkname) == "." || strings.HasPrefix(hdr.Linkname, "..") {
				//nolint:gosec // Path traversal is mitigated by the filesystem abstraction
				targetLinkName = filepath.Join(filepath.Dir(targetName), hdr.Linkname)
			} else {
				// Make the relative link absolute
				targetLinkName = "/" + filepath.Clean(hdr.Linkname)
			}
		}

		// Check for zip-slip attacks (1st pass)
		// This is mitigated by the vfs.Chroot() call above but we still want to
		// check for the case where the chrooted filesystem is bypassed or doesn't
		// work properly.
		if !strings.HasPrefix(filepath.Join(outPath, targetLinkName), filepath.Clean(outPath)+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry %s is trying to escape the destination directory", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeLink:
			// Create an absolute hardlink
			if err := out.Link(targetLinkName, targetName); err != nil {
				return fmt.Errorf("unable to create hardlink %q to %q: %w", hdr.Linkname, hdr.Name, err)
			}
		case tar.TypeSymlink:
			// Check if the target link already exists, if not, add to next pass
			if !out.Exists(targetLinkName) {
				// Add to next pass
				next = append(next, hdr)
				continue
			}

			// Create an absolute symlink
			if err := out.Symlink(targetLinkName, targetName); err != nil {
				return fmt.Errorf("unable to create symlink %q to %q: %w", hdr.Linkname, hdr.Name, err)
			}
		}
	}

	// Process next pass
	if len(next) > 0 {
		return processLinks(level+1, maxRecursionDepth, outPath, out, next)
	}

	return nil
}
