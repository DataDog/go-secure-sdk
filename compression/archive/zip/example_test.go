// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package zip

import (
	"bytes"
	"compress/flate"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing/fstest"
	"time"

	"github.com/DataDog/go-secure-sdk/ioutil"
	"github.com/DataDog/go-secure-sdk/vfs"
)

func ExampleCreate() {
	// Create in-memory test filesystem.
	// This is used to override the default bazel behaviour which creates symlinks
	// to testdata. The archive creation ignores symlinks by design which is
	// raising an error while using Bazel build.
	//
	// For nominal use case, you can use any implementation of fs.FS as input.
	root := fstest.MapFS{
		"root.txt": &fstest.MapFile{
			ModTime: time.Now(),
			Data:    []byte("root file content"),
		},
		"tmp/subfile.zip": {
			ModTime: time.Now(),
			Data:    []byte("another fake content"),
		},
	}

	// Will contains the final compressed Zip
	out := &bytes.Buffer{}

	// Create a ZIP archive
	if err := Create(root, out,
		// Change compression level
		WithCompressionLevel(flate.DefaultCompression),
		// Don't compress too small files
		WithCompressFilter(func(path string, fi fs.FileInfo) bool {
			return fi.Size() > 1024
		}),
		// Ignore .zip files
		WithExcludeFilter(func(path string, fi fs.FileInfo) bool {
			return strings.HasSuffix(path, ".zip")
		}),
	); err != nil {
		panic(err)
	}

	// Sample Output (zip built by Go are not deterministic)
	// 00000000  50 4b 03 04 14 00 08 00  00 00 17 60 48 58 00 00  |PK.........`HX..|
	// 00000010  00 00 00 00 00 00 00 00  00 00 08 00 09 00 72 6f  |..............ro|
	// 00000020  6f 74 2e 74 78 74 55 54  05 00 01 6e c2 c4 65 72  |ot.txtUT...n..er|
	// 00000030  6f 6f 74 20 66 69 6c 65  20 63 6f 6e 74 65 6e 74  |oot file content|
	// 00000040  50 4b 07 08 a0 78 c1 33  11 00 00 00 11 00 00 00  |PK...x.3........|
	// 00000050  50 4b 01 02 14 03 14 00  08 00 00 00 17 60 48 58  |PK...........`HX|
	// 00000060  a0 78 c1 33 11 00 00 00  11 00 00 00 08 00 09 00  |.x.3............|
	// 00000070  00 00 00 00 00 00 01 00  00 80 00 00 00 00 72 6f  |..............ro|
	// 00000080  6f 74 2e 74 78 74 55 54  05 00 01 6e c2 c4 65 50  |ot.txtUT...n..eP|
	// 00000090  4b 05 06 00 00 00 00 01  00 01 00 3f 00 00 00 50  |K..........?...P|
	// 000000a0  00 00 00 00 00                                    |.....|
	fmt.Println(hex.Dump(out.Bytes()))
}

func ExampleExtract() {
	// Create a root read-only filesystem from the testdata directory.
	root := os.DirFS("./testdata")

	// Create a temporary output directory
	out, err := vfs.NewTmpConfirmedDir()
	if err != nil {
		panic(err)
	}

	// Open the target tar
	archive, err := root.Open("good/3/3.zip")
	if err != nil {
		panic(err)
	}

	// The zip archive Go runtime lib requires an io.ReaderAt interface to be
	// able to manipulate the Zip buffer.
	// We have to load the content in memory and use `bytes.NewReader` to have
	// a compatible reader instance.
	buf := &bytes.Buffer{}
	size, err := ioutil.LimitCopy(buf, archive, 1<<20)
	if err != nil {
		panic(err)
	}

	// Extract the input archive from a file (limit to 1MB) to the chroot directory.
	if err := Extract(bytes.NewReader(buf.Bytes()), size, out.String()); err != nil {
		panic(err)
	}

	var names []string
	// List all extract files
	if err := fs.WalkDir(os.DirFS(out.String()), ".", func(path string, d fs.DirEntry, err error) error {
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
	// d 1
	// d 1/2
	// d 1/2/3
	// d 1/2/3/4
	// d 1/2/3/4/5
	// d 1/2/3/4/5/6
	// f 1/2/3/4/5/6/test.txt
	// f 1/2/3/4/5/test.txt
	fmt.Println(strings.Join(names, "\n"))
}
