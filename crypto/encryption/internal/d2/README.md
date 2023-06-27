# d2

Package d2 provides Modern value encryption system

## Functions

### func [Decrypt](/aead.go#L56)

`func Decrypt(key, ciphertext []byte) ([]byte, error)`

Decrypt the given ciphertext with the given key using CHACHA20+KEYED-BLAKE2B.

### func [DecryptWithAdditionalData](/aead.go#L62)

`func DecryptWithAdditionalData(key, ciphertext, aad []byte) ([]byte, error)`

DecryptWithAdditionalData decrypts the given ciphertext with the given key and
uses the additianl data during authentication.

### func [Encrypt](/aead.go#L43)

`func Encrypt(key, plaintext []byte) ([]byte, error)`

Encrypt the given plaintext with the given key using CHACHA20+KEYED-BLAKE2B.
The keys are derived using Blake2bXOF to ensure a sufficient entropy for
the encryption and the authentication.

### func [EncryptWithAdditionalData](/aead.go#L51)

`func EncryptWithAdditionalData(key, plaintext, aad []byte) ([]byte, error)`

EncryptWithAdditionalData encrypts the given plaintext with the given key and
adds the given additional data to the authentication context.
In order to decrypt the result of this function, the same additional data
must be provided to the `DecryptWithAdditionalData` function.

### func [Overhead](/aead.go#L36)

`func Overhead() int`

Overhead returns the size overhead due to encryption.
