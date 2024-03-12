# Go Secure SDK

Package security provides various security-in-mind built features across
various domains.

The package is a part of the "Secure SDK" project.

It provides a set of libraries to mitigate common security issues and
vulnerabilities. The project is designed to be a one-stop-shop for security
features and libraries for Go developers.

The project is released to the public as a set of open-source libraries to
cover Datadog open-source projects.

The project is licensed under the Apache License, Version 2.0. The license
can be found in the LICENSE file in the root of the project.

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

### func [SetFIPSMode](flags.go#L56)

`func SetFIPSMode() (revert func())`

SetFIPSMode enables the FIPS compliance mode in this package and returns a
function to revert the configuration.

Calling this method multiple times once the flag is enabled produces no effect.

## Sub Packages

* [compression](./compression): Package compression provides hardened compression related features.

* [compression/archive](./compression/archive): Package archive provides high level compressed archive management features.

* [compression/archive/tar](./compression/archive/tar): Package tar provides TAR archive management functions

* [compression/archive/tar/builder](./compression/archive/tar/builder): Package builder provides a tar archive builder essentially for testing purposes.

* [compression/archive/zip](./compression/archive/zip): Package zip provides hardened ZIP archive management functions

* [crypto/hashutil](./crypto/hashutil): Package hashutil provides secured cryptographic hash functions

* [crypto/keyutil](./crypto/keyutil): Package keyutil provides cryptographic keys management functions.

* [generator/randomness](./generator/randomness): Package randomness provides `math/rand` dropin replace with secured initialization.

* [ioutil](./ioutil): Package ioutil provides I/O hardened operations.

* [net](./net): Package net provides network security related functions.

* [net/httpclient](./net/httpclient): Package httpclient provides a SSRF-safe HTTP client implementation.

* [net/httpclient/mock](./net/httpclient/mock): Package mock is a generated GoMock package.

* [net/tlsclient](./net/tlsclient): Package tlsclient provides hardened TLS dialer functions.

* [vfs](./vfs): Package vfs extends the default Golang FS abstraction to support secured write operations.
