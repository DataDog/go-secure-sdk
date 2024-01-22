# token

Package token provides verifiable string features.

The purpose of this is to distinguish random string attack used in token
bruteforce. This feature doesn't provide authenicity, just a conformance
check.

## Variables

ErrTokenNotAuthenticated is raised when you try to validate a non compliant value.

```golang
var ErrTokenNotAuthenticated = errors.New("token: value could not be authenticated")
```

## Types

### type [Extractor](api.go#L19)

`type Extractor[T any] interface { ... }`

Extractor describes content extractor for wrapped values.

### type [GenerateOption](verifiable.go#L64)

`type GenerateOption func(*generateOption)`

GenerateOption is used to set up the token generation process.

#### func [WithTokenPrefix](verifiable.go#L75)

`func WithTokenPrefix(value string) GenerateOption`

WithTokenPrefix prepends the given prefix to the token generation so that it
will be covered by the checksum.

Prefix must match [a-z0-9-]+ regular expression (lowercase kebab case).

### type [Generator](api.go#L9)

`type Generator interface { ... }`

Generator describes token generator contract.

#### func [VerifiableUUIDGenerator](uuid.go#L57)

`func VerifiableUUIDGenerator(source UUIDGeneratorFunc, secretKey []byte) Generator`

VerifiableUUIDGenerator wraps the returned UUID byte array from the given
source to provide additional integrity protection to the content.

The secret key is used to derive a unique secret used to seal the UUID value.

```golang

// Generate an UUIDv4 (random)
uid := uuid.Must(uuid.NewRandom())

// Wrap the given UUID
tokenGenerator := VerifiableUUIDGenerator(
    StaticUUIDSource(uid),
    []byte("my-token-super-secret-key"),
)

// Generate a verifiable string associated to the given purpose.
token, err := tokenGenerator.Generate(
    WithTokenPrefix("ddogat"),
)
if err != nil {
    panic(err)
}

// Sample output: ddogat_3xGv8m7Ee2UVOk7WnFOBCE_1d8lq12WNjZlsdGKF4q0GJZd7hUhnLbyjQhVrTeD1SO6DYzgQ2eRDNM1zjWU
fmt.Println(token)

```

### type [UUIDGeneratorFunc](uuid.go#L24)

`type UUIDGeneratorFunc func() ([16]byte, error)`

UUIDGeneratorFunc represents the contract used to feed the wrapper with a
pre-generated UUID. This is used to pass the UUID byte array coming from your
favorite generator.

#### func [StaticUUIDSource](uuid.go#L27)

`func StaticUUIDSource(in [16]byte) UUIDGeneratorFunc`

StaticUUIDSource is used to set a static UUID byte array content.

#### func [UUIDv4Source](uuid.go#L34)

`func UUIDv4Source() UUIDGeneratorFunc`

UUIDv4Source generates an UUIDv4 based byte array.

### type [VerifiableGenerator](api.go#L23)

`type VerifiableGenerator interface { ... }`

#### func [VerifiableRandom](verifiable.go#L32)

`func VerifiableRandom() VerifiableGenerator`

VerifiableRandom returns a verifiable random string generator.
This implementation uses a CRC32C (Castagnoli seed) to distinguish fully
random string.

To prevent token swapping risk, we recommend you to use VerifiableRandomWithPurpose()
function with a dedicated purpose string.

This should not be used as a cryptographic proof. A digital signature process
is encouraged to provide provenance authenticity.

```golang

tokenGenerator := VerifiableRandom()

// Generate a verifiable string with a given prefix.
token, err := tokenGenerator.Generate(WithTokenPrefix("ddk"))
if err != nil {
    panic(err)
}

// Sample: ddk_0bNjIQmMJTJSYbSNDer5G8RunHcJWRO7Ukgf
fmt.Println(token)

// Verify the token format correctness and then do the database lookup to
// ensure the token authenticity
if err := tokenGenerator.Verify(token); err != nil {
    panic(err)
}

```

#### func [VerifiableRandomWithPurpose](verifiable.go#L42)

`func VerifiableRandomWithPurpose(purpose string) VerifiableGenerator`

VerifiableRandomWithPurpose returns a verifiable random string generator
associated to a dedicated purpose. All generated tokens are bound to this
specified purpose and can't be verified without the same purpose value.

This should not be used as a cryptographic proof. A digital signature process
is encouraged to provide provenance authenticity.

```golang

tokenGenerator := VerifiableRandomWithPurpose("lost-credentials-action-token")

// Generate a verifiable string associated to the given purpose.
token, err := tokenGenerator.Generate()
if err != nil {
    panic(err)
}

// Sample: 0jl9s3pHvYKf9YhXhG92CfnwLbEwpeEocMim
fmt.Println(token)

// Verify the token format correctness and then do the database lookup to
// ensure the token authenticity
if err := tokenGenerator.Verify(token); err != nil {
    panic(err)
}

```

### type [VerifiableUUIDExtractor](uuid.go#L48)

`type VerifiableUUIDExtractor interface { ... }`

VerifiableUUIDExtractor extends the Verifier to add content extraction helper.

#### func [VerifiableUUIDVerifier](uuid.go#L66)

`func VerifiableUUIDVerifier(secretKey []byte) VerifiableUUIDExtractor`

VerifiableUUIDVerifier verifies a wrapped UUID signature.

```golang
// Prepare the verifier
tokenVerifier := VerifiableUUIDVerifier(
    []byte("my-token-super-secret-key"),
)

t := "ddogat_3xGv8m7Ee2UVOk7WnFOBCE_1d8lq12WNjZlsdGKF4q0GJZd7hUhnLbyjQhVrTeD1SO6DYzgQ2eRDNM1zjWU"

// Verifiy and extract the UUID
uid, err := tokenVerifier.Extract(t)
if err != nil {
    panic(err)
}

u, err := uuid.FromBytes(uid)
if err != nil {
    panic(err)
}
```

 Output:

```
746c1439-b380-429e-9d53-6bf1b7507c10
```

### type [Verifier](api.go#L14)

`type Verifier interface { ... }`

Verifier describes token verification contract.

## Sub Packages

* [jwt](./jwt): Package jwt provides external signature mechanism for JWT token signature process.

