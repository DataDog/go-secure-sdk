# provider

Package provider provides Key provider contract and standard implementations.

## Variables

ErrKeyNotFound is raised when the key resolution failed.

```golang
var ErrKeyNotFound = errors.New("key could not be resolved from the current provider content")
```

## Types

### type [AsymmetricKey](api.go#L108)

`type AsymmetricKey interface { ... }`

AsymmetricKey describes asymmetric key provider item.

### type [Key](api.go#L98)

`type Key interface { ... }`

Key describes the item type stored in the key provider.

### type [KeyAlias](api.go#L28)

`type KeyAlias string`

KeyAlias represents key provider handle.

### type [KeyFactory](api.go#L95)

`type KeyFactory func(alias KeyAlias) (Key, error)`

KeyFactory describes key factory function.

#### func [RandomSymmetricSecret](key_factory.go#L45)

`func RandomSymmetricSecret(length int, purposes ...KeyPurpose) KeyFactory`

RandomSymmetricSecret creates a key factory based on the random raw value.

#### func [StaticPrivateKey](key_factory.go#L110)

`func StaticPrivateKey(key crypto.Signer, purposes ...KeyPurpose) KeyFactory`

StaticPrivateKey creates a key factory based on the given private key instance.

#### func [StaticPublicKey](key_factory.go#L75)

`func StaticPublicKey(key crypto.PublicKey, purposes ...KeyPurpose) KeyFactory`

StaticPublicKey creates a key factory based on the given public key instance.

#### func [StaticSymmetricSecret](key_factory.go#L18)

`func StaticSymmetricSecret(raw []byte, purposes ...KeyPurpose) KeyFactory`

StaticSymmetricSecret creates a key factory based on the given static raw value.

### type [KeyGenerator](api.go#L176)

`type KeyGenerator interface { ... }`

KeyGenerator describes key generation operations for a key provider.

### type [KeyProvider](api.go#L193)

`type KeyProvider interface { ... }`

KeyProvider represents the complete contract of a key provider.

#### func [Build](provider.go#L36)

`func Build(opts ...Option) (KeyProvider, error)`

Build an immutable key provider.

### type [KeyPurpose](api.go#L41)

`type KeyPurpose uint8`

KeyPurpose is a UInt8 value packing key capabilities as bit fields.

#### Constants

```golang
const (
    // SignaturePurpose describes the signature bit in the purpose flags for
    // the key.
    SignaturePurpose KeyPurpose = 1 + iota
    // EncryptionPurpose describes the encryption bit in the purpose flags of
    // the key.
    EncryptionPurpose
    // KeyDerivationPurpose describes the key derivation bit in the purpose
    // flags of the key.
    KeyDerivationPurpose
    // ExportableKey enables key exportation operations.
    ExportableKey
)
```

### type [KeyPurposes](api.go#L62)

`type KeyPurposes uint32`

KeyPurposes represents key purposes bit set.

#### func [Purposes](api.go#L86)

`func Purposes(purposes ...KeyPurpose) KeyPurposes`

Purposes packs key purpose together.

#### func (KeyPurposes) [Can](api.go#L65)

`func (kp KeyPurposes) Can(purpose KeyPurpose) bool`

Can check if the purpose flag is set.

#### func (KeyPurposes) [Clear](api.go#L78)

`func (kp KeyPurposes) Clear(purpose KeyPurpose) KeyPurposes`

Clear the purpose flag.

#### func (KeyPurposes) [Set](api.go#L70)

`func (kp KeyPurposes) Set(purpose KeyPurpose) KeyPurposes`

Set the purpose flag.

### type [KeyRegistry](api.go#L185)

`type KeyRegistry interface { ... }`

KeyRegistry describes key provider registry operations.

### type [KeyResolver](api.go#L166)

`type KeyResolver interface { ... }`

KeyResolver describes key resolution operations for a key provider.

### type [MutableKeyProvider](api.go#L199)

`type MutableKeyProvider interface { ... }`

MutableKeyProvider extends the KeyProvider contract to add key management operations.

#### func [New](provider.go#L31)

`func New() MutableKeyProvider`

New mutable empty key provider

### type [Option](options.go#L9)

`type Option func(*defaultProvider) error`

Option describes key provider builder option

#### func [WithEntry](options.go#L12)

`func WithEntry(alias KeyAlias, kf KeyFactory) Option`

WithEntry describes the associated with a key alias and a key factory.

### type [PrivateKey](api.go#L130)

`type PrivateKey interface { ... }`

PrivateKey describes the private side of an asymmetric key pair.

### type [PublicKey](api.go#L116)

`type PublicKey interface { ... }`

PublicKey describes the public side of an asymmetric key pair.

### type [SymmetricKey](api.go#L138)

`type SymmetricKey interface { ... }`

SymmetricKey describes symmetric key provider item.

