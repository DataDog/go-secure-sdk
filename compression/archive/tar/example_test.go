// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package tar

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing/fstest"
	"time"

	"github.com/DataDog/go-secure-sdk/vfs"
)

func ExampleCreate() {
	// Create in-memory test filesystem.
	// This is used to override the default bazel behavior which creates symlinks
	// to testdata. The archive creation ignores symlinks by design which is
	// raising an error while using Bazel build.
	//
	// For nominal use case, you can use any implementation of fs.FS as input.
	root := fstest.MapFS{
		"root.txt": &fstest.MapFile{
			ModTime: time.Now(),
			Data:    []byte("root file content"),
		},
		"tmp/subfile.tar": {
			ModTime: time.Now(),
			Data:    []byte("another fake content"),
		},
	}

	// Will contains the final compressed TAR
	out := &bytes.Buffer{}

	// Use GZIP compression
	gzw := gzip.NewWriter(out)

	// Create a TAR archive and exclude all files from "bad" directory
	if err := Create(root, gzw,
		// Exclude all files from "bad" directory
		WithExcludeFilter(
			func(path string, fi fs.FileInfo) bool {
				return strings.HasPrefix(path, "bad")
			},
		),
		// Include only files with `.tar` extension and size less than 1MB
		WithIncludeFilter(
			func(path string, fi fs.FileInfo) bool {
				return fi.Size() < 1<<20 && strings.HasSuffix(path, ".tar")
			},
		),
		// Reset all timestamps to ensure determinstic output, useful for integrity checks.
		WithHeaderRewritterFunc(ResetHeaderTimes()),
	); err != nil {
		panic(err)
	}

	// Flush and close gzip writer
	if err := gzw.Close(); err != nil {
		panic(err)
	}

	// Output:
	// 00000000  1f 8b 08 00 00 00 00 00  00 ff 2a 2e 4d 4a cb cc  |..........*.MJ..|
	// 00000010  49 d5 2b 49 2c 62 a0 15  30 80 00 5c b4 81 81 91  |I.+I,b..0..\....|
	// 00000020  09 82 0d 12 37 34 34 36  32 61 50 30 a0 99 8b 90  |....74462aP0....|
	// 00000030  40 69 31 c8 eb 06 14 db  85 ee b9 21 02 12 f3 f2  |@i1........!....|
	// 00000040  4b 32 52 8b 14 d2 12 b3  53 15 92 f3 f3 4a 52 f3  |K2R.....S....JR.|
	// 00000050  4a 06 da 4d a3 60 14 8c  82 51 30 0a 68 0f 00 01  |J..M.`...Q0.h...|
	// 00000060  00 00 ff ff ab 85 9e 6c  00 08 00 00              |.......l....|
	fmt.Println(hex.Dump(out.Bytes()))
}

func ExampleExtract() {
	// Create a root read-only filesystem from the testdata directory.
	root := os.DirFS("./testdata")

	// Create a temporary directory
	tmpDir, err := vfs.NewTmpConfirmedDir()
	if err != nil {
		panic(err)
	}

	// Open the target tar
	archive, err := root.Open("good/archive.tar")
	if err != nil {
		panic(err)
	}

	// Extract the input archive from a file (limit to 1MB) to the chroot directory.
	if err := Extract(io.LimitReader(archive, 1<<20), tmpDir.String()); err != nil {
		panic(err)
	}

	var names []string
	// List all extract files
	if err := fs.WalkDir(os.DirFS(tmpDir.String()), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			names = append(names, fmt.Sprintf("d %s", path))
		} else {
			names = append(names, fmt.Sprintf("f %s", path))
		}

		return nil
	}); err != nil {
		panic(err)
	}

	// Output:
	// d .
	// f evil.sh
	fmt.Println(strings.Join(names, "\n"))
}
