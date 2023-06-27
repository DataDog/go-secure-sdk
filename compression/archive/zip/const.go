// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package zip

import "errors"

var (
	// ErrAbortedOperation is raised when an operation has aborted for contract
	// violation reasons (File too large, etc.)
	ErrAbortedOperation = errors.New("zip: aborted operation")
	// ErrNothingArchived is raise when your selection doesn't match or exclude
	// all items from the target archive.
	ErrNothingArchived = errors.New("zip: nothing archived")
)

var (
	// Maximumn archive size
	defaultMaxArchiveSize = uint64(1 * 1024 * 1024 * 1024)
	// Maximum supported file size for archive creation
	defaultMaxFileSize = uint64(250 * 1024 * 1024)
	// Maximum entry count
	defaultMaxEntryCount = uint64(10000)
)
