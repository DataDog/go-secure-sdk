# d1

Package d1 provides FIPS compliant value encryption system

## Functions

### func [Decrypt](/aead.go#L57)

`func Decrypt(key, ciphertext []byte) ([]byte, error)`

Decrypt the given ciphertext with the given key using AES-CTR+HMAC-SHA256.

### func [DecryptWithAdditionalData](/aead.go#L63)

`func DecryptWithAdditionalData(key, ciphertext, aad []byte) ([]byte, error)`

DecryptWithAdditionalData decrypts the given ciphertext with the given key and
uses the additianl data during authentication.

### func [Encrypt](/aead.go#L44)

`func Encrypt(key, plaintext []byte) ([]byte, error)`

Encrypt the given plaintext with the given key using AES-256-CTR+HMAC-SHA256.
The keys are derived using HKDF-SHA256 to ensure a sufficient entropy for
the encryption and the authentication.

### func [EncryptWithAdditionalData](/aead.go#L52)

`func EncryptWithAdditionalData(key, plaintext, aad []byte) ([]byte, error)`

EncryptWithAdditionalData encrypts the given plaintext with the given key and
adds the given additional data to the authentication context.
In order to decrypt the result of this function, the same additional data
must be provided to the `DecryptWithAdditionalData` function.

### func [Overhead](/aead.go#L37)

`func Overhead() int`

Overhead returns the size overhead due to encryption.
