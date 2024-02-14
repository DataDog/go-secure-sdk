## 0.0.4

### Not released yet

FEATURES:

* `archive/tar`
  * Support recursive symbolic links
* `archive/zip`
  * Support recursive symbolic links
* `vfs`
  * `Chroot` ensures that the target directory is an existing directory during
    the initialization
  * Support `SymlinkFS` for FS link operations (Go 1.23)

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
