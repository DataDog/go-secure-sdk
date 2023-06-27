// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package ioutil

import (
	"errors"
	"io"
	"time"
)

// ErrReaderTimedOut is raised when the reader doesn't received data for a
// predeterminined time.
var ErrReaderTimedOut = errors.New("reader timed out")

// TimeoutReader implements a timelimited reader.
//
// This is used to mitigate slow producer attack category.
type timeoutReader struct {
	reader  io.Reader
	timeout time.Duration
}

// TimeoutReader create a timed-out limited reader instance.
func TimeoutReader(reader io.Reader, timeout time.Duration) io.Reader {
	ret := &timeoutReader{}
	ret.reader = reader
	ret.timeout = timeout
	return ret
}

// Read implements io.Reader interface.
func (r *timeoutReader) Read(buf []byte) (n int, err error) {
	// Check arguments
	if r.reader == nil {
		return 0, errors.New("reader must not be nil")
	}

	ch := make(chan bool, 1)
	n = 0
	err = nil
	go func() {
		n, err = r.reader.Read(buf)
		ch <- true
	}()

	select {
	case <-ch:
		return
	case <-time.After(r.timeout):
		return 0, ErrReaderTimedOut
	}
}
