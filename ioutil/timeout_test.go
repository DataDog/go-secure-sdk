// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package ioutil

import (
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var _ io.Reader = (*slowReader)(nil)

type slowReader struct {
	timeout time.Duration
	err     error
}

func (sr *slowReader) Read(p []byte) (n int, err error) {
	time.Sleep(sr.timeout)
	return 0, sr.err
}

func TestTimeoutReader(t *testing.T) {
	t.Run("nominal case", func(t *testing.T) {
		t.Parallel()

		tr := TimeoutReader(&slowReader{timeout: time.Millisecond, err: io.EOF}, time.Second)
		_, err := io.Copy(io.Discard, tr)
		require.NoError(t, err)
	})

	t.Run("nil reader", func(t *testing.T) {
		t.Parallel()

		tr := TimeoutReader(nil, time.Microsecond)
		_, err := io.Copy(io.Discard, tr)
		require.Error(t, err)
	})

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()

		tr := TimeoutReader(&slowReader{timeout: time.Second, err: io.EOF}, time.Microsecond)
		_, err := io.Copy(io.Discard, tr)
		require.Error(t, err)
	})
}
