# security

Package security provides various security-in-mind built features across
various domains.

## Functions

### func [InDevMode](flags.go#L19)

`func InDevMode() bool`

InDevMode returns the development mode flag status.

### func [InFIPSMode](flags.go#L47)

`func InFIPSMode() bool`

InFIPSMode returns the FIPS compliance mode flag status.

### func [SetDevMode](flags.go#L27)

`func SetDevMode() (revert func())`

SetDevMode enables the local development mode in this package and returns a
function to revert the configuration.

Calling this method multiple times once the flag is enabled produces no effect.

### func [SetFIPSMode](flags.go#L55)

`func SetFIPSMode() (revert func())`

SetFIPSMode enables the FIPS compliance mode in this package and returns a
function to revert the configuration.

Calling this method multiple times once the flag is enabled produces no effect.

## Sub Packages

* [compression](./compression): Package compression provides harded compression related features.

* [compression/archive](./compression/archive): Package archive provides high level compressed archive management features.

* [compression/archive/tar](./compression/archive/tar): Package tar provides TAR archive management functions

* [compression/archive/zip](./compression/archive/zip): Package zip provides hardened ZIP archive management functions

* [crypto/hashutil](./crypto/hashutil): Package hashutil provides secured cryptographic hash functions

* [generator/randomness](./generator/randomness): Package randomness provides `math/rand` dropin replace with secured initialization.

* [ioutil](./ioutil): Package ioutil provides I/O hardened operations.

* [ioutil/atomic](./ioutil/atomic): Package atomic provides atomic-level operations.

* [vfs](./vfs): Package vfs extends the default Golang FS abstraction to support secured write operations.

