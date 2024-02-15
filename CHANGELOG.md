## 0.0.4

### Not released yet

BREAKING-CHANGES:

* `vfs`
  * `Chroot` doesn't accept symlink to a directory as input path anymore. The
    path must be a directory to prevent confusion.

FEATURES:

* `archive/tar`
  * Support recursive symbolic links
  * `WithRestoreOwner` can be used during the extraction to restore initial
    UIG/GID attributes
  * `WithUIDGIDMapper` can be used to provide a UID/GID mapper function to remap
    attributes during the extraction
  * `WithRestoreTimes` can be used during extraction to restore Created/Modified
    timestamp attributes
* `archive/zip`
  * Support recursive symbolic links
* `vfs`
  * Support `SymlinkFS` for FS link operations (Go 1.23)

ENHANCEMENTS:

* `archive/tar`
  * Items stored using the `./` prefix in the archive are considered as absolute
    path relative the extraction path
* `vfs`
  * `Chroot` ensures that the target directory is an existing directory during
    the initialization
  * `Symlink` will create relative links when used in ChrootFS to allow extracted
    path independence
  * Files are created without `O_TRUNC` to prevent unexpected file truncation
  * Platform dependent filename filter added to prevent bad filenames and
    reserved name usages

## 0.0.3

### 2024-02-13

FEATURES:

* `archive/tar`
  * Default archive size increased to `1GB`
  * Default archive file size increased to `250MB`
  * Add missing option `WithMaxArchiveSize` to set the maximum archive file size
    that the extraction can accept.
* `archive/zip`
  * Add missing option `WithMaxArchiveSize` to set the maximum archive file size
    that the extraction can accept.
* `ioutil`
  * Improve early detection for threshold crossing for `LimitCopy`.

## 0.0.2

### 2024-02-13

BREAKING-CHANGES:

* `archive/zip`
  * Heuristical check to detect early size explosion has been removed.
  * `WithExplosionMagnitudeOrder` removed.

FEATURES:

* `archive/zip`
  * Default archive size increased to `1GB`
  * Default archive file size increased to `250MB`
  * A `UncompressedSize64` check has been added after file content copy to
    lying headers.
  * Added `WithDisableFileSizeCheck` option to disarm the file header size
    comparison.

## 0.0.1

### 2024-02-12

* Initial import
