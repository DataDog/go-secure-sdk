// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package ioutil

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrTruncatedCopy is raised when the copy is larger than expected.
var ErrTruncatedCopy = errors.New("truncated copy due to too large input")

// LimitCopy uses a buffered CopyN and a hardlimit to stop read from the reader when
// the maxSize amount of data has been written to the given writer and raise an
// error.
func LimitCopy(dst io.Writer, src io.Reader, maxSize uint64) (uint64, error) {
	writtenLength := uint64(0)

	// Check arguments
	if dst == nil {
		return 0, errors.New("writer must not be nil")
	}
	if src == nil {
		return 0, errors.New("reader must not be nil")
	}

	// Retrieve system pagesize for optimized buffer length
	pageSize := os.Getpagesize()

	// Chunked read with hard limit to reduce/prevent memory bomb.
	for {
		written, err := io.CopyN(dst, src, int64(pageSize))
		if err != nil {
			if errors.Is(err, io.EOF) {
				writtenLength += uint64(written)
				break
			}
			return writtenLength, fmt.Errorf("unable to stream source data to destination: %w", err)
		}

		// Add to length
		writtenLength += uint64(written)
	}

	// Check max size
	if writtenLength > maxSize {
		return writtenLength, ErrTruncatedCopy
	}

	// No error
	return writtenLength, nil
}
