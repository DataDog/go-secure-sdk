// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package vfs

import (
	"os"
	"strings"
	"syscall"
)

var invalidPathChars = []rune{'\x00', '/', ':'}

func isInvalidFilename(name string) bool {
	return strings.ContainsAny(name, string(invalidPathChars))
}

func createNewFile(name string) (*os.File, error) {
	return os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC|syscall.O_NOFOLLOW, 0o666)
}
