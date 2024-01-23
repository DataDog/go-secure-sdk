# encryption

Package encryption provides a high level encryption operations.

## Variables

ErrNoMatchingKey is raised when the operation can't be successful with
any given keys.

```golang
var ErrNoMatchingKey = errors.New("no matching key")
```

## Functions

### func [Open](operations.go#L19)

`func Open(keys [][]byte, ciphertext []byte, context ...[]byte) ([]byte, error)`

Open a sealed content using multiple keys.
Returns the plaintext if one key match else it returns ErrNoMatchingKey.

```golang
// Loaded previous keys from secure storage
keys := [][]byte{
    []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
    []byte("RWZLutMaZj6ea3Bf6FqGVoFquuE5jqyN"),
    []byte("ATCkaljMhYokvN08nZMX358JwPGY4DY0"),
}

// Generate a ciphertext
f, err := Value(keys[0])
if err != nil {
    panic(err)
}

// Create a session content which will be encrypted.
// We want to protect the state value from being revealed and tampered.
session := []byte(`{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}`)

// To prevent encrypted content tampering, we are going to inject additional data
// to bind the encrypted context to a specific context.
sealCtx := []byte(`{"uid":"8f41b712-663f-48a8-b43c-54cf97a94d1a"}`)

// Simulate an encrypted cookie value bound to user ID to prevent cookie swapping.
ciphertext, err := f.SealWithContext(session, sealCtx)
if err != nil {
    panic(err)
}

// Try to open session cookie value with all known keys
plaintext, err := Open(keys, ciphertext, sealCtx)
if err != nil {
    panic(err)
}
```

 Output:

```
{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}
```

### func [ParseSecretCabin](cabin.go#L65)

`func ParseSecretCabin(data, password []byte) (*memguard.LockedBuffer, error)`

ParseSecretCabin returns the secret value encoded using dog-cabin envelope.
If an incorrect password is detected an x509.IncorrectPasswordError is
returned.

Datadog cabin keys are encrypted under a password using scrypt as a KDF and
use the appropriate encryption based on the environment settings.

### func [RotateKey](operations.go#L65)

`func RotateKey(oldkeys [][]byte, newkey, ciphertext []byte, context ...[]byte) (newciphertext []byte, err error)`

RotateKey rotates encryption key used by trying to decrypt the given ciphertext
with a given key set as old keys, and try to re-encrypt the data using the new key.

```golang
// Loaded previous keys from secure storage
oldKeys := [][]byte{
    []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
    []byte("RWZLutMaZj6ea3Bf6FqGVoFquuE5jqyN"),
}
newKey := []byte("ATCkaljMhYokvN08nZMX358JwPGY4DY0")

// Create a session content
encryptedSession, err := hex.DecodeString("d222128e50db137866a225e61693a072904f38599f37517753307f9e32aa4cd847c2cd8e431b41839def11cec80df9afa88ca919b2b54a3a146318d9297a70e24138e5ee21e7f3f96bd33908baf4fd43e6a3b4c701b19faa6927d09bba8cdfc4a577e03f7c")
if err != nil {
    panic(err)
}

// Provides additional data for ciphertext authentication.
sealCtx := []byte(`{"uid":"8f41b712-663f-48a8-b43c-54cf97a94d1a"}`)

// Generate a ciphertext
newciphertext, err := RotateKey(oldKeys, newKey, encryptedSession, sealCtx)
if err != nil {
    panic(err)
}

// Try to open session cookie value with all known keys
plaintext, err := Open([][]byte{newKey}, newciphertext, sealCtx)
if err != nil {
    panic(err)
}
```

 Output:

```
{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}
```

### func [SealSecretCabin](cabin.go#L111)

`func SealSecretCabin(w io.Writer, secret *memguard.LockedBuffer, password []byte) error`

SealSecretCabin seals the input data with the given password and wrties the
envelope to the writer.

## Types

### type [ChunkedAEAD](api.go#L65)

`type ChunkedAEAD interface { ... }`

ChunkedAEAD represents all encryption/decryption operations for input stream.

#### func [Chunked](chunk.go#L15)

`func Chunked(key []byte) (ChunkedAEAD, error)`

Chunked represents a chunked stream encryption. It should be used for large
stream encryption.

```golang
key := []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB")

// Generate a ciphertext
f, err := Chunked(key)
if err != nil {
    panic(err)
}

// Create stream pipeline
pr, pw := io.Pipe()

wg := &sync.WaitGroup{}
wg.Add(1)
go func() {
    // Create writer pipeline to directly encode the encrypted output as
    // a Base64 encoded stream
    b64 := base64.NewEncoder(base64.StdEncoding, pw)

    // Create a fake file content stream (limited to 10MB)
    fileContentReader := io.LimitReader(rand.Reader, 10<<20)
    _, err := io.Copy(b64, fileContentReader)

    defer b64.Close()
    defer pw.CloseWithError(err)
    defer wg.Done()
}()

buf := &bytes.Buffer{}
if err := f.Seal(buf, pr); err != nil {
    panic(err)
}

wg.Wait()
```

 Output:

```
13985326
```

#### func [ChunkedWithMode](chunk.go#L22)

`func ChunkedWithMode(mode Mode, key []byte) (ChunkedAEAD, error)`

ChunkedWithMode represents value byte array encryption.

### type [ChunkedDecryptor](api.go#L56)

`type ChunkedDecryptor interface { ... }`

ChunkDecryptor represents chunked decryption operations.

### type [ChunkedEncryptor](api.go#L47)

`type ChunkedEncryptor interface { ... }`

ChunkEncryptor represents chunked encryption operations.

### type [Mode](api.go#L6)

`type Mode uint`

Mode represents encryption mode available.

#### Constants

```golang
const (
    // Keep 0 for automatic detection (TODO)
    // FIPS mode uses FIPS compliant encryption ciphersuites.
    // D1 => HKDF-SHA256_AES256-CTR_HMAC-SHA256
    FIPS Mode = iota + 1
    // Modern uses modern encryption ciphersuites focusing security and performance.
    // D2 => Blake2bXOF_ChaCha20_Keyed-Blake2b
    Modern
)
```

### type [ValueAEAD](api.go#L40)

`type ValueAEAD interface { ... }`

ValueAEAD represents all encryption/decryption operations for a finite byte array.

#### func [Convergent](convergent.go#L11)

`func Convergent(key []byte) (ValueAEAD, error)`

Convergent initializes a finite value encryption using deterministic
encryption system.

```golang
key := []byte("zzTPjjOhqexyMKXAxbelXOZI2lW7VM79kQXEWRPkvMnaWzlJbN1prxEk02huCpD1")

// Generate a ciphertext
f, err := Convergent(key)
if err != nil {
    panic(err)
}

// We are going to encrypt the given email.This email will be stored in a database
// and lookup will be possible from the encrypted form directly.
pii := []byte("firstname.lastname@company.com")

ciphertext, err := f.Seal(pii)
if err != nil {
    panic(err)
}
```

 Output:

```
1dtoaXXECDRvszKGTnXWpvipYTUgS36vKaWDSkcJrYcgF3M9Rh5bM2tPaBC33Ws/X9gGAqfGkLsU4L0
```

#### func [Value](value.go#L15)

`func Value(key []byte) (ValueAEAD, error)`

Value represents a finite byte array encryption. It should be used to small
content encryption to prevent excessive memory consumption.

```golang
key := []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB")

// Generate a ciphertext
f, err := Value(key)
if err != nil {
    panic(err)
}

// Create a session content which will be encrypted.
// We want to protect the state value from being revealed and tampered.
session := []byte(`{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}`)

// To prevent encrypted content tampering, we are going to inject additional data
// to bind the encrypted context to a specific context.
sealCtx := [][]byte{
    []byte("oauth-state-csrf-session"),                       // Why are you using the encryption algorithm
    []byte(`{"uid":"8f41b712-663f-48a8-b43c-54cf97a94d1a"}`), // UserID binding to ensure that the decryption is made with the exact same userID
}

// Simulate an encrypted cookie value bound to user ID to prevent cookie swapping.
ciphertext, err := f.SealWithContext(session, sealCtx...)
if err != nil {
    panic(err)
}

// Try to open session cookie value with all known keys
plaintext, err := f.OpenWithContext(ciphertext, sealCtx...)
if err != nil {
    panic(err)
}
```

 Output:

```
{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}
```

#### func [ValueWithMode](value.go#L24)

`func ValueWithMode(mode Mode, key []byte) (ValueAEAD, error)`

ValueWithMode represents value byte array encryption.

```golang
key := []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB")

// Generate a ciphertext with FIPS compliant cipher suite
f, err := ValueWithMode(FIPS, key)
if err != nil {
    panic(err)
}

// Create a session content
session := []byte(`{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}`)
sealCtx := []byte(`{"uid":"8f41b712-663f-48a8-b43c-54cf97a94d1a"}`)

// Simulate an encrypted cookie value bound to user ID to prevent cookie swapping.
ciphertext, err := f.SealWithContext(session, sealCtx)
if err != nil {
    panic(err)
}

// Try to open session cookie value with all known keys
plaintext, err := f.OpenWithContext(ciphertext, sealCtx)
if err != nil {
    panic(err)
}
```

 Output:

```
{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}
```

### type [ValueDecryptor](api.go#L31)

`type ValueDecryptor interface { ... }`

ValueDecryptor represents finite byte array decryption operations.

### type [ValueEncryptor](api.go#L22)

`type ValueEncryptor interface { ... }`

ValueEncryptor represents finite byte array encryption operations.

## Sub Packages

* [hpke](./hpke): Package hpke provides RFC9180 hybrid public key encryption features.

