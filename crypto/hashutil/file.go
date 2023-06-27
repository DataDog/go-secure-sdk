// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package hashutil

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/DataDog/go-secure-sdk/log"
)

// FileHash consumes the file content data to produce a raw checksum from the
// given crypto.Hash implementation.
func FileHash(root fs.FS, name string, hf crypto.Hash) ([]byte, error) {
	// Check arguments
	if root == nil {
		return nil, errors.New("root filesystem must not be nil")
	}

	// Try to open the target file
	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("unable to open target file %q: %w", name, err)
	}
	if f == nil {
		return nil, fmt.Errorf("returned file handle is nil")
	}
	defer func(closer io.Closer) {
		if err := closer.Close(); err != nil {
			log.Error(err).Messagef("unable to successfully close the file %q", name)
		}
	}(f)

	// Retrieve file information
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve target file information")
	}

	// Exclude invalid files
	if err := isAcceptableFileInfo(fi); err != nil {
		return nil, fmt.Errorf("not acceptable file %q: %w", name, err)
	}

	// Delegate to the reader consumer
	res, err := Hash(f, hf)
	if err != nil {
		return nil, fmt.Errorf("unable to compute file hash: %w", err)
	}

	return res, nil
}

// FileHashes consumes the file content data to produce a raw checksum from the
// given crypto.Hash implementation collection.
func FileHashes(root fs.FS, name string, hbs ...crypto.Hash) (map[crypto.Hash][]byte, error) {
	// Check arguments
	if root == nil {
		return nil, errors.New("root filesystem must not be nil")
	}

	// Try to open the target file
	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("unable to open target file %q: %w", name, err)
	}
	if f == nil {
		return nil, fmt.Errorf("returned file hanlde is nil")
	}
	defer func(closer io.Closer) {
		if err := closer.Close(); err != nil {
			log.Error(err).Messagef("unable to successfully close the file %q", name)
		}
	}(f)

	// Retrieve file information
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve target file information")
	}

	// Exclude invalid files
	if err := isAcceptableFileInfo(fi); err != nil {
		return nil, fmt.Errorf("not acceptable file %q: %w", name, err)
	}

	// Delegate to the reader consumer
	res, err := Hashes(f, hbs...)
	if err != nil {
		return nil, fmt.Errorf("unable to compute file hashes: %w", err)
	}

	return res, nil
}
