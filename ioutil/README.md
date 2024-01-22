# ioutil

Package ioutil provides I/O hardened operations.

## Variables

ErrReaderTimedOut is raised when the reader doesn't received data for a
predeterminined time.

```golang
var ErrReaderTimedOut = errors.New("reader timed out")
```

ErrTruncatedCopy is raised when the copy is larger than expected.

```golang
var ErrTruncatedCopy = errors.New("truncated copy due to too large input")
```

## Functions

### func [LimitCopy](copy.go#L16)

`func LimitCopy(dst io.Writer, src io.Reader, maxSize uint64) (uint64, error)`

LimitCopy uses a buffered CopyN and a hardlimit to stop read from the reader when
the maxSize amount of data has been written to the given writer and raise an
error.

```golang
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
```

 Output:

```
truncated copy due to too large input
```

### func [LimitWriter](limit_writer.go#L17)

`func LimitWriter(w io.Writer, limit int) io.Writer`

LimitWriter create a new Writer that accepts at most 'limit' bytes.

```golang
out := bytes.Buffer{}
lw := LimitWriter(&out, 1024)

// Copy data from the reader
_, err := io.CopyN(lw, randomness.Reader, 2048)
if err != nil {
    panic(err)
}
```

 Output:

```
1024
```

### func [TimeoutReader](timeout.go#L22)

`func TimeoutReader(reader io.Reader, timeout time.Duration) io.Reader`

TimeoutReader create a timed-out limited reader instance.

```golang
// Can be any reader (os.Stdin, Sockets, etc.)
tr := TimeoutReader(&slowReader{
    // The reader will block for 1s.
    timeout: time.Second,
    err:     io.EOF,
}, time.Millisecond)

// Copy data from the reader
_, err := io.Copy(io.Discard, tr)
```

 Output:

```
reader timed out
```

## Sub Packages

* [atomic](./atomic): Package atomic provides atomic-level operations.

