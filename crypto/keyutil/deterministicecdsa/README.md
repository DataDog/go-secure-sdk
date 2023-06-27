# deterministicecdsa

Package deterministicecdsa imports the Go 1.19.5 crypto/ecdsa package to keep deterministic key generation for a specific random source.

Golang 1.20 removed the deterministic ECDSA key geenration from a controlled random source feature.

As recommended ([https://github.com/golang/go/issues/38548#issuecomment-617409930](https://github.com/golang/go/issues/38548#issuecomment-617409930)), the code as been copied from Go
1.19.5 to restore the deterministic generation behavior.
By default, the developer should use `crypto/ecdsa` from its go runtime and use this alternative for tests
or specific usecases where the key generation is derivated from a computed random source.

Changes introduced to same thing used for RSA - [https://github.com/golang/go/commit/08f2091ce0817346458d2ae984ccea77817cd516](https://github.com/golang/go/commit/08f2091ce0817346458d2ae984ccea77817cd516)
RSA generation determinism discussion - [https://github.com/golang/go/issues/38548](https://github.com/golang/go/issues/38548)

## Functions

### func [GenerateKey](ecdsa.go#L44)

`func GenerateKey(c elliptic.Curve, rand io.Reader) (*ecdsa.PrivateKey, error)`

GenerateKey generates a public and private key pair.

