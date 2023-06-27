// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package ioutil

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

func ExampleLimitCopy() {
	// Simulate a large input
	input := strings.NewReader(strings.Repeat("A", 2048))

	// Copy decompressed data with hard limit to 1Mb.
	//
	// Why not using an io.LimitReader? Because the LimitReader truncate the
	// data without raising an error.
	_, err := LimitCopy(io.Discard, input, 1024)

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
	_, err := io.CopyN(lw, randomness.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Output: 1024
	fmt.Printf("%v", out.Len())
}
