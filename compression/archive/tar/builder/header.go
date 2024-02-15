// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"archive/tar"
	"time"
)

// HeaderModifier is a function that modifies a tar header.
type HeaderModifier func(h *tar.Header) error

// WithUID sets the UID of the header.
func WithUID(uid int) HeaderModifier {
	return func(h *tar.Header) error {
		h.Uid = uid
		return nil
	}
}

// WithGID sets the GID of the header.
func WithGID(gid int) HeaderModifier {
	return func(h *tar.Header) error {
		h.Gid = gid
		return nil
	}
}

// WithMode sets the mode of the header.
func WithMode(mode int64) HeaderModifier {
	return func(h *tar.Header) error {
		h.Mode = mode
		return nil
	}
}

// WithLinkname sets the link name of the header.
func WithLinkname(linkname string) HeaderModifier {
	return func(h *tar.Header) error {
		h.Linkname = linkname
		return nil
	}
}

// WithSize sets the size of the header.
func WithSize(size int64) HeaderModifier {
	return func(h *tar.Header) error {
		h.Size = size
		return nil
	}
}

// WithTypeflag sets the type flag of the header.
func WithTypeflag(typeFlag byte) HeaderModifier {
	return func(h *tar.Header) error {
		h.Typeflag = typeFlag
		return nil
	}
}

// WithName sets the name of the header.
func WithName(name string) HeaderModifier {
	return func(h *tar.Header) error {
		h.Name = name
		return nil
	}
}

// WithModTime sets the modification time of the header.
func WithModTime(modTime time.Time) HeaderModifier {
	return func(h *tar.Header) error {
		h.ModTime = modTime
		return nil
	}
}

// WithAccessTime sets the access time of the header.
func WithAccessTime(accessTime time.Time) HeaderModifier {
	return func(h *tar.Header) error {
		h.AccessTime = accessTime
		return nil
	}
}

// WithChangeTime sets the change time of the header.
func WithChangeTime(changeTime time.Time) HeaderModifier {
	return func(h *tar.Header) error {
		h.ChangeTime = changeTime
		return nil
	}
}
