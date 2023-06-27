# security

Package security provides various security-in-mind built features across
various domains.

## Functions

### func [InDevMode](flags.go#L23)

`func InDevMode() bool`

InDevMode returns the development mode flag status.

### func [InFIPSMode](flags.go#L51)

`func InFIPSMode() bool`

InFIPSMode returns the FIPS compliance mode flag status.

### func [SetDevMode](flags.go#L31)

`func SetDevMode() (revert func())`

SetDevMode enables the local development mode in this package and returns a
function to revert the configuration.

Calling this method multiple times once the flag is enabled produces no effect.

### func [SetFIPSMode](flags.go#L59)

`func SetFIPSMode() (revert func())`

SetFIPSMode enables the FIPS compliance mode in this package and returns a
function to revert the configuration.

Calling this method multiple times once the flag is enabled produces no effect.

## Sub Packages

* [compression](./compression): Package compression provides harded compression related features.

* [compression/archive](./compression/archive): Package archive provides high level compressed archive management features.

* [compression/archive/tar](./compression/archive/tar): Package tar provides TAR archive management functions

* [compression/archive/zip](./compression/archive/zip): Package zip provides hardened ZIP archive management functions

* [crypto](./crypto): Package crypto provides standardized and company wide cryptographic features.

* [crypto/canonicalization](./crypto/canonicalization): Package cryptographically usable canonicalization process.

* [crypto/certutil](./crypto/certutil): Package certutil provides X.509 Certificate related functions.

* [crypto/encryption](./crypto/encryption): Package encryption provides a high level encryption operations.

* [crypto/hashutil](./crypto/hashutil): Package hashutil provides secured cryptographic hash functions

* [crypto/keyutil](./crypto/keyutil): Package keyutil provides cryptographic keys management functions.

* [crypto/keyutil/deterministicecdsa](./crypto/keyutil/deterministicecdsa): Package deterministicecdsa imports the Go 1.19.5 crypto/ecdsa package to keep deterministic key generation for a specific random source.

* [crypto/keyutil/provider](./crypto/keyutil/provider): Package provider provides Key provider contract and standard implementations.

* [crypto/signature](./crypto/signature): Package signature provides Signature related primitives.

* [crypto/signature/envelope](./crypto/signature/envelope): Package envelope provides Envelope signature scheme.

* [crypto/signature/test/mock](./crypto/signature/test/mock): Package mock is a generated GoMock package.

* [crypto/tlsconfig](./crypto/tlsconfig): Package tlsconfig provides default TLS configuration settings.

* [generator](./generator): Package generator provides various security related generators.

* [generator/passphrase](./generator/passphrase): Package passphrase provides passphrase generation based on DiceWare.

* [generator/password](./generator/password): Package password provides a library for generating high-entropy random password strings via the crypto/rand package.

* [generator/randomness](./generator/randomness): Package randomness provides `math/rand` dropin replace with secured initialization.

* [ioutil](./ioutil): Package ioutil provides I/O hardened operations.

* [ioutil/atomic](./ioutil/atomic): Package atomic provides atomic-level operations.

* [log](./log): Package log provides a high level logger abstraction.

* [net](./net): Package net provides network security related functions.

* [net/httpclient](./net/httpclient): Package httpclient provides a SSRF-safe HTTP client implementation.

* [net/httpclient/mock](./net/httpclient/mock): Package mock is a generated GoMock package.

* [net/safehttp](./net/safehttp): Package safehttp provides hardened HTTP related default functions.

* [value](./value): Package value provides security enhanced Go types to protect from value leaks.

* [value/transformer](./value/transformer): Package transformer provides value transformers for value wrappers.

* [vfs](./vfs): Package vfs extends the default Golang FS abstraction to support secured write operations.

