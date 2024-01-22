# password

Package password provides cryptographic hash function used for password storage.

This package implements the recommendations from the [OWASP Password Storage Cheat Sheet]([https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)).

For more information about Password storage strategies at Datadog - [https://dtdg.co/skb-secure-password-storage](https://dtdg.co/skb-secure-password-storage)

## Variables

```golang
var (
    // ErrInvalidHash is raised when caller tries to use a invalid encoded hash.
    ErrInvalidHash = errors.New("invalid hash")
    // ErrStrategyNotSupported is raised when caller tries to use a strategy which is not supported.
    ErrStrategyNotSupported = errors.New("given strategy is not supported")
)
```

ErrNotInitialized is returned when the default instance is not initialized

```golang
var ErrNotInitialized = errors.New("default instance not initialized")
```

## Functions

### func [FixedNonce](nonce.go#L9)

`func FixedNonce(salt []byte) func() []byte`

FixedNonce returns a nonce factory that returns the given salt

### func [Hash](globals.go#L20)

`func Hash(password []byte) (string, error)`

Hash password using default instance

### func [NeedsEncodingUpgrade](globals.go#L38)

`func NeedsEncodingUpgrade(encoded string) bool`

NeedsEncodingUpgrade returns the password hash upgrade need when DefaultAlgorithm is changed

### func [RandomNonce](nonce.go#L16)

`func RandomNonce(length int) func() []byte`

RandomNonce returns a nonce factory that returns a random length bound salt

### func [Verify](globals.go#L30)

`func Verify(encoded string, password []byte) (bool, error)`

Verify password using default instance

## Types

### type [Hasher](api.go#L29)

`type Hasher interface { ... }`

Hasher represents password hasher contract.

#### func [New](hasher.go#L12)

`func New(options ...Option) (Hasher, error)`

New hasher instance is built according options

```golang

// Use a pepper seed to increase password bruteforce in a potential data leak.
// This value should be stored in your secret storage.
serverPepperSeed := []byte(`pqIuaay0eBymivqgmpY6oJ5szDOKMoIWCAM8vXmWVm9Lwj4xwVymOAjsN0HTeA1`)

// Create a new password hasher instance
h, err := New(
    // Enable FIPS compliance strategy
    WithFIPSCompliance(),
    // Enable password peppering for defense in depth
    WithPepper(serverPepperSeed),
)
if err != nil {
    panic(err)
}

// Encode the given password
encoded, err := h.Hash([]byte("my-secure-password"))
if err != nil {
    panic(err)
}

// Sample output: hAIBWCAq6kKaWJde0I5t5cVy0FwWeNWA25YoOWRwMchIQY9PSVhAoYeasejuFGiBLmRJ6DVd7I+7W8ohy5AMmWC10J56eV4k7AYf3emuHQeLux1SX96DeNWp12qo5wuhoOPHWFLbAA
fmt.Println(encoded)

```

### type [Option](options.go#L6)

`type Option func(*defaultHasher)`

Option is the hasher option setting function signature

#### func [WithFIPSCompliance](options.go#L16)

`func WithFIPSCompliance() Option`

WithFIPSCompliance enables FIPS-140-2 password hashing

#### func [WithPepper](options.go#L24)

`func WithPepper(value []byte) Option`

WithPepper defines the password peppering value

#### func [WithSaltFunc](options.go#L9)

`func WithSaltFunc(factory func() []byte) Option`

WithSaltFunc defines the salt factory value for salt generation

