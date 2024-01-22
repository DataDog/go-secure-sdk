# transformer

Package transformer provides value transformers for value wrappers.

## Variables

ErrImpossibleOperation is raised when the callee tried to execute an
irreversible operation.

```golang
var ErrImpossibleOperation = errors.New("impossible transformer operation request")
```

## Types

### type [RemoteKMSEncryption](kms.go#L15)

`type RemoteKMSEncryption interface { ... }`

RemoteKMSEncryption aggregates required interface for the transformer.

### type [Transformer](api.go#L11)

`type Transformer interface { ... }`

Transformer describes value transformater contract.

#### func [Encryption](encryption.go#L10)

`func Encryption(aead encryption.ValueAEAD) Transformer`

Encryption initializes an encryption value transformer.

#### func [Hash](hash.go#L10)

`func Hash(hasher func() hash.Hash) Transformer`

Hash initializes a transformer

#### func [Identity](identity.go#L4)

`func Identity() Transformer`

Identity initializes a transformer which doesn't alter the given value.

#### func [KMS](kms.go#L34)

`func KMS(srv RemoteKMSEncryption) Transformer`

KMS initializes an KMS-based encryption value transformer. To prevent data
moves, the data is locally encrypted with a randomly generated encryption key
called the data encryption key (DEK). This key is encrypted by the remote KMS
to protect the DEK.

Be aware of the transactional cost applied to the usage of this transformer.
Each operation calls the remote KMS service, the overall performance is
strictly bound to the remote KMS service performance and its reachability
cost.

This transformer is not recommended to be used with atomic structure fields,
please consider wrapping a complex object to reduce transformer calls.
By using this transformer in an inappropriate way, you could be responsible
for a KMS outage.

