package ioutil

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"time"
)

func ExampleLimitCopy() {
	root := os.DirFS("./testdata")

	// Open 1Gb gzip bomb
	bomb, err := root.Open("1g.gz")
	if err != nil {
		panic(err)
	}

	// Pass through the GZIP decompression reader
	gzr, err := gzip.NewReader(bomb)
	if err != nil {
		panic(err)
	}

	// Copy decompressed data with hard limit to 1Mb.
	//
	// Why not using an io.LimitReader? Because the LimitReader truncate the
	// data without raising an error.
	_, err = LimitCopy(io.Discard, gzr, 1024)

	// Output: truncated copy due to too large input
	fmt.Printf("%v", err)
}

func ExampleTimeoutReader() {
	// Can be any reader (os.Stdin, Sockets, etc.)
	tr := TimeoutReader(&slowReader{
		// The reader will block for 1s.
		timeout: time.Second,
		err:     io.EOF,
	}, time.Millisecond)

	// Copy data from the reader
	_, err := io.Copy(io.Discard, tr)

	// Output: reader timed out
	fmt.Printf("%v", err)
}

func ExampleLimitWriter() {
	out := bytes.Buffer{}
	lw := LimitWriter(&out, 1024)

	// Copy data from the reader
	_, err := io.CopyN(lw, rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Output: 1024
	fmt.Printf("%v", out.Len())
}
