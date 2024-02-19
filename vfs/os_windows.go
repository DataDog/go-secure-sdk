// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package vfs

import (
	"os"
	"strings"
)

var (
	// https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file
	invalidPathChars = string("\x00" + `/\:*?"<>|`)
	reservedNames    = map[string]struct{}{
		"CON": {}, "PRN": {}, "AUX": {}, "NUL": {},
		"COM1": {}, "COM2": {}, "COM3": {}, "COM4": {}, "COM5": {}, "COM6": {},
		"COM7": {}, "COM8": {}, "COM9": {}, "COM0": {},
		"LPT1": {}, "LPT2": {}, "LPT3": {}, "LPT4": {}, "LPT5": {}, "LPT6": {},
		"LPT7": {}, "LPT8": {}, "LPT9": {}, "LPT0": {},
	}
)

func isInvalidFilename(name string) bool {
	_, found := reservedNames[strings.ToUpper(name)]
	return found || strings.ContainsAny(name, invalidPathChars) || strings.HasSuffix(name, " ") || strings.HasSuffix(name, ".")
}

func createNewFile(name string) (*os.File, error) {
	return os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0o666)
}

func chown(name string, uid, gid int) error {
	// Retrieve the file info to check if it's a symlink.
	fi, err := os.Lstat(name)
	if err != nil {
		return err
	}

	// Ensure consistent behavior with other platforms.
	if fi.Mode()&os.ModeSymlink != 0 {
		return &os.PathError{Op: "chown", Path: name, Err: os.ErrInvalid}
	}

	return nil
}

func chmod(name string, mode os.FileMode) error {
	// Retrieve the file info to check if it's a symlink.
	fi, err := os.Lstat(name)
	if err != nil {
		return err
	}

	// Ensure consistent behavior with other platforms.
	if fi.Mode()&os.ModeSymlink != 0 {
		return &os.PathError{Op: "chmod", Path: name, Err: os.ErrInvalid}
	}

	// Change the file mode.
	return os.Chmod(name, mode)
}
