package tar

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/DataDog/go-secure-sdk/ioutil"
	"github.com/DataDog/go-secure-sdk/vfs"
)

// Extract TAR content from the reader to the given outPath prefix.
//
// outPath must be controlled by the developer and verified before being used as
// the extraction path.
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

		// Clean file path.
		targetPath := filepath.Clean(hdr.Name)
		if targetPath == "." {
			continue
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

	// Post process symlinks
	for _, hdr := range symlinks {
		targetName := filepath.Clean(hdr.Name)

		// Absolute or relative symlink
		var targetLinkName string
		if filepath.IsAbs(hdr.Linkname) {
			targetLinkName = filepath.Clean(hdr.Linkname)
		} else {
			//nolint:gosec // Path traversal is mitigated by the filesystem abstraction
			targetLinkName = filepath.Join(filepath.Dir(targetName), hdr.Linkname)
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

	return nil
}
