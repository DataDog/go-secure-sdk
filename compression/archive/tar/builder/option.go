// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// Option is a function that configures the builder.
type Option func(tw *tar.Writer) error

// FS adds a file system to the archive.
func FS(fsys fs.FS) Option {
	return func(tw *tar.Writer) error {
		// Ensure the root actually exists before trying to tar it
		rootFi, err := fs.Stat(fsys, ".")
		if err != nil {
			return fmt.Errorf("unable to tar files: %w", err)
		}
		if !rootFi.IsDir() {
			return errors.New("root path must be a directory")
		}

		return tw.AddFS(fsys)
	}
}

// File adds a file to the archive.
func File(name string, r io.Reader, hm ...HeaderModifier) Option {
	return func(tw *tar.Writer) error {
		// Check arguments
		if r == nil {
			return errors.New("reader must not be nil")
		}

		// Read the file data
		data, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("unable to read file data: %w", err)
		}

		// Create a new file entry
		hdr := &tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(data)),
		}
		for _, m := range hm {
			if err := m(hdr); err != nil {
				return fmt.Errorf("unable to modify tar header: %w", err)
			}
		}

		// Write the header
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("unable to write tar header: %w", err)
		}

		// Write the file data
		if _, err := tw.Write(data); err != nil {
			return fmt.Errorf("unable to write file data: %w", err)
		}

		return nil
	}
}

// Dir adds a directory to the archive.
func Dir(name string, hm ...HeaderModifier) Option {
	return func(tw *tar.Writer) error {
		// Create a new directory entry
		hdr := &tar.Header{
			Name: name,
			Mode: 0700,
			Typeflag: tar.TypeDir,
		}
		for _, m := range hm {
			if err := m(hdr); err != nil {
				return fmt.Errorf("unable to modify tar header: %w", err)
			}
		}

		// Write the header
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("unable to write tar header: %w", err)
		}

		return nil
	}
}

// Hardlink adds a hard link to the archive.
func Hardlink(name, target string, hm ...HeaderModifier) Option {
	return func(tw *tar.Writer) error {
		// Create a new hard link entry
		hdr := &tar.Header{
			Name:     name,
			Linkname: target,
			Mode:     0600,
			Typeflag: tar.TypeLink,
		}
		for _, m := range hm {
			if err := m(hdr); err != nil {
				return fmt.Errorf("unable to modify tar header: %w", err)
			}
		}

		// Write the header
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("unable to write tar header: %w", err)
		}

		return nil
	}
}

// Symlink adds a symbolic link to the archive.
func Symlink(name, target string, hm ...HeaderModifier) Option {
	return func(tw *tar.Writer) error {
		// Create a new symbolic link entry
		hdr := &tar.Header{
			Name:     name,
			Linkname: target,
			Mode:     0600,
			Typeflag: tar.TypeSymlink,
		}
		for _, m := range hm {
			if err := m(hdr); err != nil {
				return fmt.Errorf("unable to modify tar header: %w", err)
			}
		}

		// Write the header
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("unable to write tar header: %w", err)
		}

		return nil
	}
}
