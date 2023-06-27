# atomic

Package atomic provides atomic-level operations.

## Functions

### func [WriteFile](write_file.go#L21)

`func WriteFile(filename string, r io.Reader) (err error)`

WriteFile atomically replace the file content of the filename target by the
reader content. If an error occurs the temporary file is deleted and nothing
is touched.

```golang

// Large and sensitive content to be written atomically
var r io.Reader

// The file will be created next to the destination, then the content will
// wrtittent and finally if everything succeeded the target file will be
// replaced.
// Any error during the process will leave the existing file intact.
if err := WriteFile("configuration.json", r); err != nil {
    panic(err)
}

```

