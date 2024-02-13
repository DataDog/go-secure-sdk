# tar

Package tar provides TAR archive management functions

This package with hardened controls to protect the caller from various attack
related to insecure compression management.

## Variables

```golang
var (
    // ErrAbortedOperation is raised when an operation has aborted for contract
    // violation reasons (File too large, etc.)
    ErrAbortedOperation = errors.New("tar: aborted operation")
    // ErrNothingArchived is raise when your selection doesn't match or exclude
    // all items from the target archive.
    ErrNothingArchived = errors.New("tar: nothing archived")
)
```

## Functions

### func [Create](create.go#L21)

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
```

 Output:

```
00000000  1f 8b 08 00 00 00 00 00  00 ff 2a 2e 4d 4a cb cc  |..........*.MJ..|
00000010  49 d5 2b 49 2c 62 a0 15  30 80 00 5c b4 81 81 91  |I.+I,b..0..\....|
00000020  09 82 0d 12 37 34 34 36  32 61 50 30 a0 99 8b 90  |....74462aP0....|
00000030  40 69 31 c8 eb 06 14 db  85 ee b9 21 02 12 f3 f2  |@i1........!....|
00000040  4b 32 52 8b 14 d2 12 b3  53 15 92 f3 f3 4a 52 f3  |K2R.....S....JR.|
00000050  4a 06 da 4d a3 60 14 8c  82 51 30 0a 68 0f 00 01  |J..M.`...Q0.h...|
00000060  00 00 ff ff ab 85 9e 6c  00 08 00 00              |.......l....|
```

### func [Extract](extract.go#L28)

`func Extract(r io.Reader, outPath string, opts ...Option) error`

Extract TAR content from the reader to the given outPath prefix.

outPath must be controlled by the developer and verified before being used as
the extraction path.
The extraction process is protected against zip-slip attacks, limited in terms
of file count, and file size.

```golang
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
```

 Output:

```
d .
f evil.sh
```

## Types

### type [FileInfoFilterFunc](options.go#L28)

`type FileInfoFilterFunc func(path string, fi fs.FileInfo) bool`

FileInfoFilterFunc declares the function type used to take a boolean decision
based on the path and the associated file information.

### type [HeaderProcessorFunc](options.go#L31)

`type HeaderProcessorFunc func(hdr *tar.Header) *tar.Header`

HeaderProcessorFunc declares the function type used to pre-process Tar item headers.

#### func [ResetHeaderTimes](options.go#L89)

`func ResetHeaderTimes() HeaderProcessorFunc`

ResetHeaderTimes returns a header processor used to reset Tar header times.
Useful to get deterministic output.

### type [Option](options.go#L24)

`type Option func(*options)`

Option declares operation functional option.

#### func [WithEmptyDirectories](options.go#L72)

`func WithEmptyDirectories(value bool) Option`

WithEmptyDirectories sets a flag to add directories during compression.

#### func [WithExcludeFilter](options.go#L57)

`func WithExcludeFilter(value FileInfoFilterFunc) Option`

WithExcludeFilter defines the function used to determine if an item should
be excluded from the archive.

#### func [WithHeaderRewritterFunc](options.go#L79)

`func WithHeaderRewritterFunc(value HeaderProcessorFunc) Option`

WithHeaderRewritterFunc sets the Tar item header rewritter interceptor.

#### func [WithIncludeFilter](options.go#L49)

`func WithIncludeFilter(value FileInfoFilterFunc) Option`

WithIncludeFilter defines the function used to determine if an item should
be included in the archive.

#### func [WithMaxEntryCount](options.go#L34)

`func WithMaxEntryCount(value uint64) Option`

WithMaxEntryCount overrides the default maximum entry count in the archive (directories and files).

#### func [WithMaxFileSize](options.go#L41)

`func WithMaxFileSize(value uint64) Option`

WithMaxFileSize overrides the default maximum file size for compression.

#### func [WithOverwriteFilter](options.go#L65)

`func WithOverwriteFilter(value FileInfoFilterFunc) Option`

WithOverwriteFilter defines the function used to determine if an item should
be overwritten during archive extraction.

