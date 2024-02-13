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
