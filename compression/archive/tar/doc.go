// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

// Package tar provides TAR archive management functions
//
// This package with hardened controls to protect the caller from various attack
// related to insecure compression management.
//
// This package provides a simple API to create and extract TAR archives.
//
// These features are supported:
// - Create a TAR archive from a Golang filesystem interface
// - Extract a TAR archive to a directory
// - Limit the size of the archive and the size of the files
// - Limit the number of files in the archive
// - Limit the number of symlink recursion in the archive
// - Symbolic and hard links
// - File/Directory permissions restoration
// - File/Directory ownership restoration (disabled by default)
// - File/Directory time attributes restoration (disabled by default)
//
// This package provides the following security features:
// - Protect against item name attacks
// - Protect against item count attacks
// - Protect against item size attacks
// - Protect against zip-slip attacks
// - Protect against link recursion attacks
// - Protect against path traversal attacks (chrooted extraction)
//
// This package is limited by the Go standard library and does not support
// advanced features such as:
// - Symlink handling to unexistant files/directories
// - Hardlink handling to unexistant files/directories
package tar
