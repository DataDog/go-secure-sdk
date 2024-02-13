# zip

Package zip provides hardened ZIP archive management functions

This package with hardened controls to protect the caller from various attack
related to insecure compression management.

## Variables

```golang
var (
    // ErrAbortedOperation is raised when an operation has aborted for contract
    // violation reasons (File too large, etc.)
    ErrAbortedOperation = errors.New("zip: aborted operation")
    // ErrNothingArchived is raise when your selection doesn't match or exclude
    // all items from the target archive.
    ErrNothingArchived = errors.New("zip: nothing archived")
)
```

## Functions

### func [Create](create.go#L22)

`func Create(fileSystem fs.FS, w io.Writer, opts ...Option) error`

Create an archive from given options to the given writer.

```golang

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

```

### func [Extract](extract.go#L26)

`func Extract(r io.ReaderAt, size uint64, outPath string, opts ...Option) error`

Extract ZIP content from the reader to the given outPath prefix.

outPath must be controlled by the developer and verified before being used as
the extraction path.

```golang
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
```

 Output:

```
d .
d 1
d 1/2
d 1/2/3
d 1/2/3/4
d 1/2/3/4/5
d 1/2/3/4/5/6
f 1/2/3/4/5/6/test.txt
f 1/2/3/4/5/test.txt
```

## Types

### type [FileInfoFilterFunc](options.go#L31)

`type FileInfoFilterFunc func(path string, fi fs.FileInfo) bool`

FileInfoFilterFunc declares the function type used to take a boolean decision
based on the path and the associated file information.

### type [HeaderProcessorFunc](options.go#L34)

`type HeaderProcessorFunc func(hdr *zip.FileHeader) *zip.FileHeader`

HeaderProcessorFunc declares the function type used to pre-process ZIP item headers.

#### func [ResetHeaderTimes](options.go#L115)

`func ResetHeaderTimes() HeaderProcessorFunc`

ResetHeaderTimes returns a header processor used to reset Zip header times.
Useful to get deterministic output.

### type [Option](options.go#L27)

`type Option func(*options)`

Option declares operation functional option.

#### func [WithCompressFilter](options.go#L75)

`func WithCompressFilter(value FileInfoFilterFunc) Option`

WithCompressFilter defines the function used to determine if an item should
be compressed into the archive.

#### func [WithCompressionLevel](options.go#L37)

`func WithCompressionLevel(value int) Option`

WithCompressionLevel defines the compression level used during the compression.

#### func [WithDisableFileSizeCheck](options.go#L105)

`func WithDisableFileSizeCheck(value bool) Option`

WithDisableFileSizeCheck sets a flag to disable the file size check during
decompression.

#### func [WithEmptyDirectories](options.go#L90)

`func WithEmptyDirectories(value bool) Option`

WithEmptyDirectories sets a flag to add directories during compression.

#### func [WithExcludeFilter](options.go#L67)

`func WithExcludeFilter(value FileInfoFilterFunc) Option`

WithExcludeFilter defines the function used to determine if an item should
be excluded from the archive.

#### func [WithHeaderRewritterFunc](options.go#L97)

`func WithHeaderRewritterFunc(value HeaderProcessorFunc) Option`

WithHeaderRewritterFunc sets the Tar item header rewritter interceptor.

#### func [WithIncludeFilter](options.go#L59)

`func WithIncludeFilter(value FileInfoFilterFunc) Option`

WithIncludeFilter defines the function used to determine if an item should
be included in the archive.

#### func [WithMaxEntryCount](options.go#L44)

`func WithMaxEntryCount(value uint64) Option`

WithMaxEntryCount overrides the default maximum entry count in the archive (directories and files).

#### func [WithMaxFileSize](options.go#L51)

`func WithMaxFileSize(value uint64) Option`

WithMaxFileSize overrides the default maximum file size for compression.

#### func [WithOverwriteFilter](options.go#L83)

`func WithOverwriteFilter(value FileInfoFilterFunc) Option`

WithOverwriteFilter defines the function used to determine if an item should
be overwritten during archive extraction.

