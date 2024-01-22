# kem

Package kem provides Key Encapsulation Mechanism used to derive a shared secret
from asymmetric materials.

## Variables

```golang
var (
    // ErrDeserialization is raised when the given material can't be decoded as
    // the expected key type.
    ErrDeserialization = errors.New("unable to deserialize key content")
    // ErrEncap is raised when an error occurred during shared secret encapsulation.
    ErrEncap = errors.New("unable to encapsulate the shared secret")
    // ErrDecap is raised when an error occurred during shared secret decapsulation.
    ErrDecap = errors.New("unable to decapsulate the shared secret")
)
```

## Types

### type [Scheme](api.go#L10)

`type Scheme interface { ... }`

Scheme defines the default KEM suite contract.

#### func [DHP256HKDFSHA256](api.go#L32)

`func DHP256HKDFSHA256() Scheme`

DHP256HKDFSHA256 defines a KEM Suite based on P-256 curve with HKDF-SHA256
for shared secret derivation.

#### func [DHP384HKDFSHA384](api.go#L47)

`func DHP384HKDFSHA384() Scheme`

DHP384HKDFSHA384 defines a KEM Suite based on P-384 curve with HKDF-SHA384
for shared secret derivation.

#### func [DHP521HKDFSHA512](api.go#L62)

`func DHP521HKDFSHA512() Scheme`

DHP521HKDFSHA512 defines a KEM Suite based on P-521 curve with HKDF-SHA512
for shared secret derivation.

#### func [DHX25519HKDFSHA256](api.go#L77)

`func DHX25519HKDFSHA256() Scheme`

DHX25519HKDFSHA256 defines a KEM Suite based on Curve25519 curve with
HKDF-SHA256 for shared secret derivation.

