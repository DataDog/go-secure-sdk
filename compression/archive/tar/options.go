// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package tar

import (
	"archive/tar"
	"io/fs"
	"time"
)

type options struct {
	MaxArchiveSize      uint64
	MaxEntryCount       uint64
	MaxFileSize         uint64
	MaxSymlinkRecursion uint64
	IncludeFilter       FileInfoFilterFunc
	ExcludeFilter       FileInfoFilterFunc
	OverwriteFilter     FileInfoFilterFunc
	AddEmptyDirectories bool
	HeaderRewritter     HeaderProcessorFunc
}

// Option declares operation functional option.
type Option func(*options)

// FileInfoFilterFunc declares the function type used to take a boolean decision
// based on the path and the associated file information.
type FileInfoFilterFunc func(path string, fi fs.FileInfo) bool

// HeaderProcessorFunc declares the function type used to pre-process Tar item headers.
type HeaderProcessorFunc func(hdr *tar.Header) *tar.Header

// WithMaxArchiveSize overrides the default maximum archive size.
func WithMaxArchiveSize(value uint64) Option {
	return func(o *options) {
		o.MaxArchiveSize = value
	}
}

// WithMaxEntryCount overrides the default maximum entry count in the archive (directories and files).
func WithMaxEntryCount(value uint64) Option {
	return func(o *options) {
		o.MaxEntryCount = value
	}
}

// WithMaxFileSize overrides the default maximum file size for compression.
func WithMaxFileSize(value uint64) Option {
	return func(o *options) {
		o.MaxFileSize = value
	}
}

// WithMaxSymlinkRecursion overrides the default maximum symlink recursion depth.
func WithMaxSymlinkRecursion(value uint64) Option {
	return func(o *options) {
		o.MaxSymlinkRecursion = value
	}
}

// WithIncludeFilter defines the function used to determine if an item should
// be included in the archive.
func WithIncludeFilter(value FileInfoFilterFunc) Option {
	return func(o *options) {
		o.IncludeFilter = value
	}
}

// WithExcludeFilter defines the function used to determine if an item should
// be excluded from the archive.
func WithExcludeFilter(value FileInfoFilterFunc) Option {
	return func(o *options) {
		o.ExcludeFilter = value
	}
}

// WithOverwriteFilter defines the function used to determine if an item should
// be overwritten during archive extraction.
func WithOverwriteFilter(value FileInfoFilterFunc) Option {
	return func(o *options) {
		o.OverwriteFilter = value
	}
}

// WithEmptyDirectories sets a flag to add directories during compression.
func WithEmptyDirectories(value bool) Option {
	return func(o *options) {
		o.AddEmptyDirectories = value
	}
}

// WithHeaderRewritterFunc sets the Tar item header rewritter interceptor.
func WithHeaderRewritterFunc(value HeaderProcessorFunc) Option {
	return func(o *options) {
		o.HeaderRewritter = value
	}
}

// -----------------------------------------------------------------------------

// ResetHeaderTimes returns a header processor used to reset Tar header times.
// Useful to get deterministic output.
func ResetHeaderTimes() HeaderProcessorFunc {
	return func(hdr *tar.Header) *tar.Header {
		if hdr == nil {
			return nil
		}

		hdr.AccessTime = time.Time{}
		hdr.ChangeTime = time.Time{}
		hdr.ModTime = time.Time{}

		return hdr
	}
}
