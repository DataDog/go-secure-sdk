package ioutil

import (
	"errors"
	"io"
)

// LimitWriter implements io.Writer and writes the data to an io.Writer, but
// limits the total bytes written to it, dropping the remaining bytes on the
// floor.
type limitWriter struct {
	writer io.Writer
	limit  int
}

// LimitWriter create a new Writer that accepts at most 'limit' bytes.
func LimitWriter(w io.Writer, limit int) io.Writer {
	return &limitWriter{
		writer: w,
		limit:  limit,
	}
}

//nolint:wrapcheck // return direct writer error
func (lw *limitWriter) Write(p []byte) (int, error) {
	lp := len(p)

	// Check arguments
	if lw.writer == nil {
		return 0, errors.New("output writer must not be nil")
	}

	var err error
	if lw.limit > 0 {
		if lp > lw.limit {
			p = p[:lw.limit]
		}
		lw.limit -= len(p)
		_, err = lw.writer.Write(p)
	}

	return lp, err
}
