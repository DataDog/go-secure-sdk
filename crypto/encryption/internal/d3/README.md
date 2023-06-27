# d3

Package d3 provides FIPS compliant chunked encryption system

## Constants

```golang
const (
    MagicVersion = 0xD3
)
```

## Functions

### func [Decrypt](/aead.go#L71)

`func Decrypt(dst io.Writer, ciphertext io.Reader, key []byte) error`

Decrypt the given ciphertext with the given key using HKDF_SHA256+AES-GCM.

### func [DecryptWithAdditionalData](/aead.go#L77)

`func DecryptWithAdditionalData(dst io.Writer, ciphertext io.Reader, key, aad []byte) error`

DecryptWithAdditionalData decrypts the given ciphertext with the given key and
uses the additianl data during authentication.

### func [Encrypt](/aead.go#L58)

`func Encrypt(dst io.Writer, plaintext io.Reader, key []byte) error`

Encrypt the given plaintext with the given key using HKDF_SHA256+AES-GCM.
The keys are derived using HKDF_SHA-512 to ensure a sufficient entropy for
the encryption and the authentication.

### func [EncryptWithAdditionalData](/aead.go#L66)

`func EncryptWithAdditionalData(dst io.Writer, plaintext io.Reader, key, aad []byte) error`

EncryptWithAdditionalData encrypts the given plaintext with the given key and
adds the given additional data to the authentication context.
In order to decrypt the result of this function, the same additional data
must be provided to the `DecryptWithAdditionalData` function.

### func [EncryptedLength](/aead.go#L42)

`func EncryptedLength(plaintextLength int) int`

EncryptedLength returns the encrypted length matching the plaintext length.
