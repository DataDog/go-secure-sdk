# builder

Package builder provides a tar archive builder essentially for testing purposes.

## Types

### type [ArchiveBuilder](builder.go#L20)

`type ArchiveBuilder struct { ... }`

ArchiveBuilder is a tar archive builder.

#### func [New](builder.go#L13)

`func New(w io.Writer) *ArchiveBuilder`

New creates a new tar archive builder.

#### func (*ArchiveBuilder) [Close](builder.go#L35)

`func (b *ArchiveBuilder) Close() error`

Close closes the tar writer.

#### func (*ArchiveBuilder) [With](builder.go#L25)

`func (b *ArchiveBuilder) With(bf ...Option) (*ArchiveBuilder, error)`

With applies the given options to the builder.

### type [HeaderModifier](header.go#L12)

`type HeaderModifier func(h *tar.Header) error`

HeaderModifier is a function that modifies a tar header.

#### func [WithAccessTime](header.go#L79)

`func WithAccessTime(accessTime time.Time) HeaderModifier`

WithAccessTime sets the access time of the header.

#### func [WithChangeTime](header.go#L87)

`func WithChangeTime(changeTime time.Time) HeaderModifier`

WithChangeTime sets the change time of the header.

#### func [WithGID](header.go#L23)

`func WithGID(gid int) HeaderModifier`

WithGID sets the GID of the header.

#### func [WithLinkname](header.go#L39)

`func WithLinkname(linkname string) HeaderModifier`

WithLinkname sets the link name of the header.

#### func [WithModTime](header.go#L71)

`func WithModTime(modTime time.Time) HeaderModifier`

WithModTime sets the modification time of the header.

#### func [WithMode](header.go#L31)

`func WithMode(mode int64) HeaderModifier`

WithMode sets the mode of the header.

#### func [WithName](header.go#L63)

`func WithName(name string) HeaderModifier`

WithName sets the name of the header.

#### func [WithSize](header.go#L47)

`func WithSize(size int64) HeaderModifier`

WithSize sets the size of the header.

#### func [WithTypeflag](header.go#L55)

`func WithTypeflag(typeFlag byte) HeaderModifier`

WithTypeflag sets the type flag of the header.

#### func [WithUID](header.go#L15)

`func WithUID(uid int) HeaderModifier`

WithUID sets the UID of the header.

### type [Option](option.go#L15)

`type Option func(tw *tar.Writer) error`

Option is a function that configures the builder.

#### func [Dir](option.go#L74)

`func Dir(name string, hm ...HeaderModifier) Option`

Dir adds a directory to the archive.

#### func [FS](option.go#L18)

`func FS(fsys fs.FS) Option`

FS adds a file system to the archive.

#### func [File](option.go#L34)

`func File(name string, r io.Reader, hm ...HeaderModifier) Option`

File adds a file to the archive.

#### func [Hardlink](option.go#L98)

`func Hardlink(name, target string, hm ...HeaderModifier) Option`

Hardlink adds a hard link to the archive.

#### func [Symlink](option.go#L123)

`func Symlink(name, target string, hm ...HeaderModifier) Option`

Symlink adds a symbolic link to the archive.

