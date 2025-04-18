// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package hashutil

import (
	"errors"
	"io/fs"
)

// isAcceptableFileInfo returns an error if the given fileinformation is not
// acceptable for hashing purpose.
func isAcceptableFileInfo(fi fs.FileInfo) error {
	// Exclude invalid files
	switch {
	case fi == nil:
		return errors.New("file information must not be nil")
	case fi.IsDir():
		return errors.New("unable to hash a directory")
	case !fi.Mode().IsRegular():
		return errors.New("the target is not a regular file")
	case fi.Size() < 0:
		return errors.New("file size must not be negative")
	//nolint:gosec // False positive, uint64(fi.Size()) is not negative.
	case uint64(fi.Size()) > maxHashContent:
		return errors.New("file too large to be hashed")
	default:
		// ok
	}

	return nil
}
