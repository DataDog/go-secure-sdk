# d5

Package d5 provides FIPS compliant deterministic encryption system

Convergent encryption, also known as content hash keying, is a cryptosystem
that produces identical ciphertext from identical plaintext files.
To accomplish this, the encryption system is implemented by removing the
indistinguishability (IND) property of a classic encryption system.

Hence this algorithm must be used with plain knowledge of its usage
consequences.

> Consider migrating to AES-GCM-SIV once integrated in Go runtime - [https://github.com/golang/go/issues/54364](https://github.com/golang/go/issues/54364).

## Algorithm

```ruby
encKey := HKDF(SHA256, secret, "datadog-convergent-encryption-key-v1")
nonceKey := HKDF(SHA256, secret, "datadog-convergent-encryption-nonce-v1")
nonce := HMAC(SHA256, nonceKey, message)
encrypted := AEAD_ENCRYPT(encKey, nonce, message)

final := nonce || encrypted

decKey := HKDF(SHA256, secret, "datadog-convergent-encryption-key-v1")
plaintext := AEAD_DECRYPT(decKey, nonce, encrypted)
```

## Additional References

* [Attacks on Convergent Encryption]([https://tahoe-lafs.org/hacktahoelafs/drew_perttula.html](https://tahoe-lafs.org/hacktahoelafs/drew_perttula.html))

## Constants

```golang
const (
    MagicVersion = 0xD5
)
```

## Functions

### func [Decrypt](/aead.go#L54)

`func Decrypt(key, ciphertext []byte) ([]byte, error)`

Decrypt the given ciphertext with the given key using AES-256-GCM.

### func [DecryptWithAdditionalData](/aead.go#L60)

`func DecryptWithAdditionalData(key, ciphertext, aad []byte) ([]byte, error)`

DecryptWithAdditionalData decrypts the given ciphertext with the given key and
uses the additianl data during authentication.

### func [Encrypt](/aead.go#L41)

`func Encrypt(key, plaintext []byte) ([]byte, error)`

Encrypt the given plaintext with the given key using AES-256-GCM with a
deterministic 32 bytes nonce generation based on HMAC-SHA256 of the plaintext.

### func [EncryptWithAdditionalData](/aead.go#L49)

`func EncryptWithAdditionalData(key, plaintext, aad []byte) ([]byte, error)`

EncryptWithAdditionalData encrypts the given plaintext with the given key and
adds the given additional data to the authentication context.
In order to decrypt the result of this function, the same additional data
must be provided to the `DecryptWithAdditionalData` function.

### func [Overhead](/aead.go#L34)

`func Overhead() int`

Overhead returns the size overhead due to encryption.
