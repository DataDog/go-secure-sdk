# vfs

Package vfs extends the default Golang FS abstraction to support secured
write operations.

## Constants

```golang
const (
    Separator = string(filepath.Separator)
    SelfDir   = "."
    ParentDir = ".."
)
```

## Types

### type [ConfirmedDir](confirmeddir.go#L15)

`type ConfirmedDir string`

ConfirmedDir is a clean, absolute, delinkified path
that was confirmed to point to an existing directory.

#### func [ConfirmDir](filesystem.go#L15)

`func ConfirmDir(root FileSystem, path string) (ConfirmedDir, error)`

ConfirmDir returns an error if the user-specified path is not an existing
directory on root.
Otherwise, ConfirmDir returns path, which can be relative, as a ConfirmedDir
and all that implies.

```golang
// Chroot to temporary directory
root, err := Chroot(os.TempDir())
if err != nil {
    panic(err)
}

// Use the filesystem to resolve the real target path.
cdir, err := ConfirmDir(root, ".")
if err != nil {
    panic(err)
}
```

 Output:

```
.
```

#### func [NewTmpConfirmedDir](confirmeddir.go#L20)

`func NewTmpConfirmedDir() (ConfirmedDir, error)`

NewTmpConfirmedDir returns a temporary dir, else error.
The directory is cleaned, no symlinks, etc. so it's
returned as a ConfirmedDir.

```golang
// Create and resolve a confirmed temporary directory
// For MacOS, the final directory is resolved from its symbolic link.
cdir, err := NewTmpConfirmedDir()
if err != nil {
    panic(err)
}

// Try to escape from the confirmed directory
cdir1 := cdir.Join("../etc/password")

// Check new path validity
isValid := cdir.HasPrefix(ConfirmedDir(cdir1))
```

 Output:

```
false
```

#### func (ConfirmedDir) [HasPrefix](confirmeddir.go#L36)

`func (d ConfirmedDir) HasPrefix(path ConfirmedDir) bool`

HasPrefix ensure that the given path has the confirmed directory as prefix.

#### func (ConfirmedDir) [Join](confirmeddir.go#L46)

`func (d ConfirmedDir) Join(path string) string`

Join the given path to the confirmed directory.

#### func (ConfirmedDir) [String](confirmeddir.go#L50)

`func (d ConfirmedDir) String() string`

### type [ConstraintError](chroot.go#L28)

`type ConstraintError struct { ... }`

ConstraintError records an error and the operation and file that
violated it.

#### func (*ConstraintError) [Error](chroot.go#L35)

`func (e *ConstraintError) Error() string`

Error returns the formatted error string for the ConstraintError.

#### func (*ConstraintError) [Unwrap](chroot.go#L40)

`func (e *ConstraintError) Unwrap() error`

Unwrap implements error unwrapping.

### type [File](api.go#L19)

`type File interface { ... }`

File represents the file writer interface.

### type [FileSystem](api.go#L26)

`type FileSystem interface { ... }`

FileSystem extends the default read-only filesystem abstraction to add write
operations.

#### func [Chroot](chroot.go#L15)

`func Chroot(root string) (FileSystem, error)`

Chroot returns a chrooted filesystem assuming an OS base filesystem as root
filesystem.

```golang
// Chroot to temporary directory
root, err := Chroot(os.TempDir())
if err != nil {
    panic(err)
}

// Chroot is compatible with Go fs.FS abstraction
if err := fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
    // Do something
    return nil
}); err != nil {
    panic(err)
}

// Provides filesystem isolation to prevent path traversal.
err = root.Mkdir("../wrong", 0o700)

fsErr := &ConstraintError{}
switch {
case err == nil:
    // No error
case errors.As(err, &fsErr):
    // Constraint error
default:
    // Other error
}
```

 Output:

```
IsConstraintError => true
```

#### func [ChrootFS](filesystem.go#L38)

`func ChrootFS(root FileSystem, path string) (FileSystem, error)`

ChrootFS creates a chrooted filesystem instance from the given filesystem and
the path.
The path must be a directory part of the given root filesystem to be used.

```golang

// Chroot to temporary directory
root, err := Chroot(os.TempDir())
if err != nil {
    panic(err)
}

// Create a chroot from a parent filesystem.
subRoot, err := ChrootFS(root, "var")
if err != nil {
    panic(err)
}

// Try to open an out of chroot file will raise a ConstraintError.
_, err = subRoot.Open("../etc/passwd")
switch {
case err == nil:
    // No error
default:
    // Other error
}

```

#### func [OS](os.go#L13)

`func OS() FileSystem`

```golang

// Create a host writeable filesystem without constraints.
root := OS()

// Create a chroot from a parent filesystem.
subRoot, err := ChrootFS(root, "/etc/datadog")
if err != nil {
    panic(err)
}

// Try to open an out of chroot file will raise a ConstraintError.
_, err = subRoot.Open("../passwd")
switch {
case err == nil:
    // No error
default:
    // Other error
}

```

