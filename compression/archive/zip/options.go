package zip

import (
	"archive/zip"
	"io/fs"
	"time"
)

type options struct {
	CompressionLevel           int
	MaxArchiveSize             uint64
	MaxEntryCount              uint64
	MaxFileSize                uint64
	MaxExplosionMagnitudeOrder uint64
	IncludeFilter              FileInfoFilterFunc
	ExcludeFilter              FileInfoFilterFunc
	CompressFilter             FileInfoFilterFunc
	OverwriteFilter            FileInfoFilterFunc
	AddEmptyDirectories        bool
	HeaderRewritter            HeaderProcessorFunc
}

// Option declares operation functional option.
type Option func(*options)

// FileInfoFilterFunc declares the function type used to take a boolean decision
// based on the path and the associated file information.
type FileInfoFilterFunc func(path string, fi fs.FileInfo) bool

// HeaderProcessorFunc declares the function type used to pre-process ZIP item headers.
type HeaderProcessorFunc func(hdr *zip.FileHeader) *zip.FileHeader

// WithCompressionLevel defines the compression level used during the compression.
func WithCompressionLevel(value int) Option {
	return func(o *options) {
		o.CompressionLevel = value
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

// WithMaxExplosionMagnitudeOrder overrides the default maximum size explosion
// magnitude order.
func WithMaxExplosionMagnitudeOrder(value uint64) Option {
	return func(o *options) {
		o.MaxExplosionMagnitudeOrder = value
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

// WithCompressFilter defines the function used to determine if an item should
// be compressed into the archive.
func WithCompressFilter(value FileInfoFilterFunc) Option {
	return func(o *options) {
		o.CompressFilter = value
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

// ResetHeaderTimes returns a header processor used to reset Zip header times.
// Useful to get deterministic output.
func ResetHeaderTimes() HeaderProcessorFunc {
	return func(hdr *zip.FileHeader) *zip.FileHeader {
		if hdr == nil {
			return nil
		}

		hdr.SetModTime(time.Time{})

		return hdr
	}
}
