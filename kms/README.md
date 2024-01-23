# kms

Package kms provides KMS implementation abstraction API.

## Types

### type [Decryptor](api.go#L14)

`type Decryptor interface { ... }`

Decryptor describes decryption operations contract.

### type [Encryptor](api.go#L9)

`type Encryptor interface { ... }`

Encryptor describes encryption operations contract.

### type [KeyExporter](api.go#L44)

`type KeyExporter interface { ... }`

KeyExporter represents secret key exporter contract.

### type [KeyRotator](api.go#L29)

`type KeyRotator interface { ... }`

KeyRotator represents key rotation operations contract.

### type [KeyType](api.go#L63)

`type KeyType int`

KeyType represents the type of the key

#### Constants

```golang
const (
    KeyTypeUnknown KeyType = iota
    KeyTypeSymmetric
    KeyTypeRSA
    KeyTypeEd25519
    KeyTypeECDSA
    KeyTypeHMAC
)
```

### type [PublicKeyExporter](api.go#L34)

`type PublicKeyExporter interface { ... }`

PublicKeyExporter represents public key operations contract.

### type [Service](api.go#L51)

`type Service interface { ... }`

Service represents the Vault Transit backend operation service contract.

### type [Signer](api.go#L19)

`type Signer interface { ... }`

Signer represents signature creation operations contract.

### type [VerificationPublicKeyExporter](api.go#L39)

`type VerificationPublicKeyExporter interface { ... }`

VerificationPublicKeyExporter represents verification public key exporter contract.

### type [Verifier](api.go#L24)

`type Verifier interface { ... }`

Verifier represents signature verification operations contract.

## Sub Packages

* [mock](./mock): Package mock is a generated GoMock package.

* [vault](./vault): Package vault implements KMS abstraction API to provide Hashicorp Vault support.

