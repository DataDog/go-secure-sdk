# transformer

Package transformer provides value transformers for value wrappers.

## Variables

ErrImpossibleOperation is raised when the callee tried to execute an
irreversible operation.

```golang
var ErrImpossibleOperation = errors.New("impossible transformer operation request")
```

## Types

### type [Transformer](api.go#L14)

`type Transformer interface { ... }`

Transformer describes value transformater contract.

#### func [Encryption](encryption.go#L13)

`func Encryption(aead encryption.ValueAEAD) Transformer`

Encryption initializes an encryption value transformer.

#### func [Hash](hash.go#L13)

`func Hash(hasher func() hash.Hash) Transformer`

Hash initializes a transformer

#### func [Identity](identity.go#L7)

`func Identity() Transformer`

Identity initializes a transformer which doesn't alter the given value.

