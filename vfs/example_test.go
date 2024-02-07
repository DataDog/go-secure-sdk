// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

func ExampleChroot() {
	// Chroot to temporary directory
	root, err := Chroot(os.TempDir())
	if err != nil {
		panic(err)
	}

	// Chroot is compatible with Go fs.FS abstraction
	if err := fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		// Do something
		return nil
	}); err != nil {
		panic(err)
	}

	// Provides filesystem isolation to prevent path traversal.
	err = root.Mkdir("../wrong", 0o700)

	fsErr := &ConstraintError{}
	switch {
	case err == nil:
		// No error
	case errors.As(err, &fsErr):
		// Constraint error
	default:
		// Other error
	}

	// Output: IsConstraintError => true
	fmt.Printf("IsConstraintError => %v", errors.As(err, &fsErr))
}

func ExampleChrootFS() {
	// Chroot to temporary directory
	root, err := Chroot(os.TempDir())
	if err != nil {
		panic(err)
	}

	// Create a chroot from a parent filesystem.
	subRoot, err := ChrootFS(root, "var")
	if err != nil {
		panic(err)
	}

	// Try to open an out of chroot file will raise a ConstraintError.
	_, err = subRoot.Open("../etc/passwd")
	switch {
	case err == nil:
		// No error
	default:
		// Other error
	}
}

func ExampleOS() {
	// Create a host writeable filesystem without constraints.
	root := OS()

	// Create a chroot from a parent filesystem.
	subRoot, err := ChrootFS(root, "/etc/datadog")
	if err != nil {
		panic(err)
	}

	// Try to open an out of chroot file will raise a ConstraintError.
	_, err = subRoot.Open("../passwd")
	switch {
	case err == nil:
		// No error
	default:
		// Other error
	}
}

func ExampleNewTmpConfirmedDir() {
	// Create and resolve a confirmed temporary directory
	// For MacOS, the final directory is resolved from its symbolic link.
	cdir, err := NewTmpConfirmedDir()
	if err != nil {
		panic(err)
	}

	// Try to escape from the confirmed directory
	cdir1 := cdir.Join("../etc/password")

	// Check new path validity
	isValid := cdir.HasPrefix(ConfirmedDir(cdir1))

	// Output: false
	fmt.Println(isValid)
}

func ExampleConfirmDir() {
	// Chroot to temporary directory
	root, err := Chroot(os.TempDir())
	if err != nil {
		panic(err)
	}

	// Use the filesystem to resolve the real target path.
	cdir, err := ConfirmDir(root, ".")
	if err != nil {
		panic(err)
	}

	// Output: .
	fmt.Printf("%v", cdir)
}
