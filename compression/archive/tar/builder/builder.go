// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

// Package builder provides a tar archive builder essentially for testing purposes.
package builder

import (
	"archive/tar"
	"io"
)

// New creates a new tar archive builder.
func New(w io.Writer) *ArchiveBuilder {
	return &ArchiveBuilder{
		tw: tar.NewWriter(w),
	}
}

// ArchiveBuilder is a tar archive builder.
type ArchiveBuilder struct {
	tw *tar.Writer
}

// With applies the given options to the builder.
func (b *ArchiveBuilder) With(bf ...Option) *ArchiveBuilder {
	for _, o := range bf {
		o(b.tw)
	}
	return b
}

// Close closes the tar writer.
func (b *ArchiveBuilder) Close() error {
	return b.tw.Close()
}
