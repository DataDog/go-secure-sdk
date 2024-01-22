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

* [authentication](./authentication): Package authentication provides various authentication mechanisms.

* [authentication/httpsig](./authentication/httpsig): Package httpsig provides request authentication based on IETF HTTP message signature.

* [authentication/privatejwt](./authentication/privatejwt): Package privatejwt provides asymmetric client authentication based on a signed assertion authentication.

* [authorization](./authorization): Package authorization provides a simple interface for authorization.

* [compression](./compression): Package compression provides harded compression related features.

* [compression/archive](./compression/archive): Package archive provides high level compressed archive management features.

* [compression/archive/tar](./compression/archive/tar): Package tar provides TAR archive management functions

* [compression/archive/zip](./compression/archive/zip): Package zip provides hardened ZIP archive management functions

* [crypto](./crypto): Package crypto provides standardized and company wide cryptographic features.

* [crypto/canonicalization](./crypto/canonicalization): Package cryptographically usable canonicalization process.

* [crypto/certutil](./crypto/certutil): Package certutil provides X.509 Certificate related functions.

* [crypto/encryption](./crypto/encryption): Package encryption provides a high level encryption operations.

* [crypto/encryption/hpke](./crypto/encryption/hpke): Package hpke provides RFC9180 hybrid public key encryption features.

* [crypto/hashutil](./crypto/hashutil): Package hashutil provides secured cryptographic hash functions

* [crypto/hashutil/password](./crypto/hashutil/password): Package password provides cryptographic hash function used for password storage.

* [crypto/kem](./crypto/kem): Package kem provides Key Encapsulation Mechanism used to derive a shared secret from asymmetric materials.

* [crypto/keyutil](./crypto/keyutil): Package keyutil provides cryptographic keys management functions.

* [crypto/keyutil/deterministicecdsa](./crypto/keyutil/deterministicecdsa): Package deterministicecdsa imports the Go 1.19.5 crypto/ecdsa package to keep deterministic key generation for a specific random source.

* [crypto/keyutil/provider](./crypto/keyutil/provider): Package provider provides Key provider contract and standard implementations.

* [crypto/signature](./crypto/signature): Package signature provides Signature related primitives.

* [crypto/signature/envelope](./crypto/signature/envelope): Package envelope provides Envelope signature scheme.

* [crypto/signature/test/mock](./crypto/signature/test/mock): Package mock is a generated GoMock package.

* [crypto/tlsconfig](./crypto/tlsconfig): Package tlsconfig provides default TLS configuration settings.

* [encoding](./encoding): Package encoding provides various encoding strategies.

* [encoding/basex](./encoding/basex): Package basex provides fast base encoding / decoding of any given alphabet.

* [generator](./generator): Package generator provides various security related generators.

* [generator/passphrase](./generator/passphrase): Package passphrase provides passphrase generation based on DiceWare.

* [generator/password](./generator/password): Package password provides a library for generating high-entropy random password strings via the crypto/rand package.

* [generator/randomness](./generator/randomness): Package randomness provides `math/rand` dropin replace with secured initialization.

* [generator/token](./generator/token): Package token provides verifiable string features.

* [generator/token/jwt](./generator/token/jwt): Package jwt provides external signature mechanism for JWT token signature process.

* [ioutil](./ioutil): Package ioutil provides I/O hardened operations.

* [ioutil/atomic](./ioutil/atomic): Package atomic provides atomic-level operations.

* [kms](./kms): Package kms provides KMS implementation abstraction API.

* [kms/mock](./kms/mock): Package mock is a generated GoMock package.

* [kms/vault](./kms/vault): Package vault implements KMS abstraction API to provide Hashicorp Vault support.

* [kms/vault/logical](./kms/vault/logical): Package logical is a generated GoMock package.

* [net](./net): Package net provides network security related functions.

* [net/httpclient](./net/httpclient): Package httpclient provides a SSRF-safe HTTP client implementation.

* [net/httpclient/mock](./net/httpclient/mock): Package mock is a generated GoMock package.

* [net/safehttp](./net/safehttp): Package safehttp provides hardened HTTP related default functions.

* [net/tlsclient](./net/tlsclient): Package tlsclient provides hardened TLS dialer functions.

* [privacy](./privacy): Package privacy provides security functions to work with privacy sensitive data.

* [privacy/encryption](./privacy/encryption): Package encryption provides encryption based privacy features.

* [privacy/encryption/fpe](./privacy/encryption/fpe): Package fpe provides Format Preserving Encryption based helpers.

* [privacy/encryption/fpe/ff3](./privacy/encryption/fpe/ff3): Package ff3 provides FF3-1 format preserving encryption primitives.

* [privacy/masking](./privacy/masking): Package masking provides various data masking used to reduce data value relevance and linkability.

* [value](./value): Package value provides security enhanced Go types to protect from value leaks.

* [value/transformer](./value/transformer): Package transformer provides value transformers for value wrappers.

* [vfs](./vfs): Package vfs extends the default Golang FS abstraction to support secured write operations.

