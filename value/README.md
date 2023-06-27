# value

Package value provides security enhanced Go types to protect from value leaks.

## Functions

### func [SetDefaultEncryptionKey](defaults.go#L71)

`func SetDefaultEncryptionKey(key []byte) error`

SetDefaultEncryptionKey sets the encryption key used for default value encryption.

### func [SetDefaultTokenizationKey](defaults.go#L87)

`func SetDefaultTokenizationKey(key []byte) error`

SetDefaultTokenizationKey sets the HMAC-SHA256 key used for default tokenization.

## Types

### type [Redacted](redacted_secret.go#L35)

`type Redacted[T any] struct { ... }`

Redacted describes a redacted value to prevnt its leak.

#### func [AsRedacted](redacted_secret.go#L26)

`func AsRedacted[T any](value T) Redacted[T]`

AsRedacted wraps a given value as a redacted value.

```golang
// Use a strong type to represents secret value
var secret Redacted[string]

// Assign the secret value
secret.value = "password"
```

 Output:

```
password
[redacted]
```

#### func (Redacted[T]) [Format](redacted_secret.go#L71)

`func (Redacted[T]) Format(f fmt.State, c rune)`

Format implements string formatter.
Implements fmt.Formatter

#### func (Redacted[T]) [GoString](redacted_secret.go#L65)

`func (Redacted[T]) GoString() string`

GoString implements alternative string interface.
Implements fmt.GoStringer

#### func (Redacted[T]) [MarshalBinary](redacted_secret.go#L41)

`func (Redacted[T]) MarshalBinary() ([]byte, error)`

MarshalBinary marshals the secreat as a redacted text.
Implements encoding.BinaryMarshaler.

#### func (Redacted[T]) [MarshalJSON](redacted_secret.go#L53)

`func (Redacted[T]) MarshalJSON() ([]byte, error)`

MarshalJSON marshals the string as a redacted one.
Implements json.Marshaler

#### func (Redacted[T]) [MarshalText](redacted_secret.go#L47)

`func (Redacted[T]) MarshalText() ([]byte, error)`

MarshalText marshals the secret as a redacted text.
Implements encoding.TextMarshaler

#### func (Redacted[T]) [String](redacted_secret.go#L59)

`func (Redacted[T]) String() string`

String implements string interface.
Implements fmt.Stringer

#### func (*Redacted[T]) [Unwrap](redacted_secret.go#L78)

`func (s *Redacted[T]) Unwrap() T`

Unwrap returns the wrapped secret value.

### type [Wrapped](wrapped_value.go#L44)

`type Wrapped[T any] struct { ... }`

Wrapped describes sensitive string value.

#### func [AsEncrypted](defaults.go#L51)

`func AsEncrypted[T any](v T) Wrapped[T]`

AsEncrypted returns a wrapped value which will encrypt its value when trying
to access its value for printing/serializing purpose.

Encrypted values are deserializable.

```golang

// Prepare a configuration state
type credentials struct {
    User     string `json:"user"`
    Password string `json:"password"`
}

type configuration struct {
    Server      string               `json:"server"`
    Credentials Wrapped[credentials] `json:"credentials"`
}

out, err := json.Marshal(&configuration{
    Server: "pgsql://127.0.0.1:5432/production",
    Credentials: AsEncrypted(credentials{
        User:     "app-runner-12345",
        Password: "secret password",
    }),
})
if err != nil {
    panic(err)
}

// Sample Output: {"server":"pgsql://127.0.0.1:5432/production","credentials":"0tZUAiEGkBzhRPoIrRtntDuojTTBJ-ekwgG4ShvyCOA5RcPGS6_L-O8gkDVCEI6FMSIP4dpVRrHUYSFq7o0GSH08GcQA-dlP3ohSOam1mxd-SYqMq8Mzmr5johGd7Gtl7u-c2KNLG3m1hMexl76iXbQ"}
fmt.Println(string(out))

```

#### func [AsToken](defaults.go#L34)

`func AsToken[T any](v T) Wrapped[T]`

AsToken returns a wrapped types which will hash its value when trying to
access its value for printing/serializing purpose.

Tokens are not deserializable.

```golang
// Assign specific global tokenization key
if err := SetDefaultTokenizationKey([]byte("000-deterministic-tokenization-key")); err != nil {
    panic(err)
}

// Use a strong type to represents secret value
secret := AsToken("firstname.lastname@company.tld")
```

 Output:

```
firstname.lastname@company.tld
m9BAmfJ5duXmaIn2IKW1VuFP60ZlFFuJBTD1Ytp6eKQ
```

#### func [AsWrapped](wrapped_value.go#L34)

`func AsWrapped[T any](value T, t transformer.Transformer) Wrapped[T]`

AsWrapped wraps a given value as a secret.

```golang
// Prepare an event to log
type event struct {
    Timestamp time.Time `json:"@timestamp"`
    Level     string    `json:"@level"`
    Message   any
}

// Assign specific global tokenization key
if err := SetDefaultTokenizationKey([]byte("000-deterministic-tokenization-key")); err != nil {
    panic(err)
}

// Prepare explicit secret leak
type login struct {
    Principal Wrapped[string]  `json:"principal"`
    Secret    Redacted[string] `json:"secret"`
}

out, err := json.Marshal(&event{
    Timestamp: time.Date(2023, time.March, 8, 15, 25, 18, 123, time.UTC),
    Level:     "info",
    Message: &login{
        Principal: AsWrapped("user", transformer.Hash(sha256.New)),
        Secret:    AsRedacted("should not be logged"),
    },
})
if err != nil {
    panic(err)
}
```

 Output:

```
{"@timestamp":"2023-03-08T15:25:18.000000123Z","@level":"info","Message":{"principal":"MZDSYdGGrurTqN7sICc3x3da9cjUVanlupWMSLX9P1k","secret":"[redacted]"}}
```

#### func (Wrapped[T]) [Format](wrapped_value.go#L177)

`func (s Wrapped[T]) Format(f fmt.State, c rune)`

Format implements string formatter.
Implements fmt.Formatter

#### func (Wrapped[T]) [GoString](wrapped_value.go#L171)

`func (s Wrapped[T]) GoString() string`

GoString implements alternative string interface.
Implements fmt.GoStringer

#### func (Wrapped[T]) [MarshalBinary](wrapped_value.go#L51)

`func (s Wrapped[T]) MarshalBinary() ([]byte, error)`

MarshalBinary marshals the secreat as a encrypted byte array.
Implements encoding.BinaryMarshaler.

#### func (Wrapped[T]) [MarshalJSON](wrapped_value.go#L111)

`func (s Wrapped[T]) MarshalJSON() ([]byte, error)`

MarshalJSON marshals the string as a redacted one.
Implements json.Marshaler

#### func (Wrapped[T]) [MarshalText](wrapped_value.go#L86)

`func (s Wrapped[T]) MarshalText() ([]byte, error)`

MarshalText marshals the secret as a encrypted text.
Implements encoding.TextMarshaler

#### func (*Wrapped[T]) [Scan](wrapped_value.go#L151)

`func (s *Wrapped[T]) Scan(src interface{ ... }) error`

Scan unmarshals a secret secret from a SQL record.
Implements sql.Scanner.

#### func (Wrapped[T]) [String](wrapped_value.go#L165)

`func (s Wrapped[T]) String() string`

String implements string interface.
Implements xml.Marshaler

#### func (*Wrapped[T]) [UnmarshalBinary](wrapped_value.go#L69)

`func (s *Wrapped[T]) UnmarshalBinary(in []byte) error`

UnmarshalBinary unmarshals a sealed secret and rturnts the decrypted value.
Implements encoding.BinaryUnmarshaler.

#### func (*Wrapped[T]) [UnmarshalJSON](wrapped_value.go#L128)

`func (s *Wrapped[T]) UnmarshalJSON(in []byte) error`

UnmarshalJSON unmarshals the secret from the encrypted value.
Implements json.Marshaler

#### func (*Wrapped[T]) [UnmarshalText](wrapped_value.go#L98)

`func (s *Wrapped[T]) UnmarshalText(in []byte) error`

UnmarshalText unmarshals a sealed secret and rturnts the decrypted value.
Implements encoding.TextUnmarshaler.

#### func (*Wrapped[T]) [Unwrap](wrapped_value.go#L188)

`func (s *Wrapped[T]) Unwrap() T`

Unwrap returns the wrapped secret value.

#### func (Wrapped[T]) [Value](wrapped_value.go#L139)

`func (s Wrapped[T]) Value() (driver.Value, error)`

Value marshals the sealed secret to be stored in a string column record.
Implements driver.Valuer.

## Sub Packages

* [transformer](./transformer): Package transformer provides value transformers for value wrappers.

