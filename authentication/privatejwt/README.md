# privatejwt

Package privatejwt provides asymmetric client authentication based on a signed assertion authentication.

## Variables

ErrExpiredAssertion is raised when the expiration is reached.

```golang
var ErrExpiredAssertion = errors.New("the assertion is expired")
```

## Types

### type [Claims](claims.go#L14)

`type Claims struct { ... }`

Claims describes the assertion properties.

#### func (*Claims) [Validate](claims.go#L24)

`func (c *Claims) Validate(clientID, audience string, now time.Time) error`

Validate the current claims coherence.

### type [ClientKeysResolver](api.go#L18)

`type ClientKeysResolver func(ctx context.Context, id string) ([]*jose.JSONWebKey, error)`

ClientKeysResolver respresents client identity lookup contract.

### type [Signer](api.go#L21)

`type Signer interface { ... }`

Signer describes attestation signer contract.

#### func [AssertionSigner](jwt.go#L45)

`func AssertionSigner(assertionType string, key *jose.JSONWebKey, clientID string, expiration time.Duration) (Signer, error)`

AssertionSigner instantiates a JWT client assertion signer.

The signer key must be a private key encoded using JWK dedicated to signature
purpose. This will produce an assertion from the ClientID identified as the
issuer and the subject of this assertion. The generated assertion will be
acceptable for the given expiration delay which must be bounded between
10 seconds and 10 minutes.

EdDSA is disabled in FIPS mode.
HMAC (HS*) based are disabled by design due to their lack of authentication.
If the given key has a certificate, it will be embedded in the assertion.

```golang

// Decode the key as a JWK
var pk jose.JSONWebKey
if err := json.Unmarshal(clientPrivateJWK, &pk); err != nil {
    panic(err)
}

// Create a client assertion signer.
signer, err := AssertionSigner("runner-client", &pk, "123456789", 5*time.Minute)
if err != nil {
    panic(err)
}

// Create client assertion targeting the given endpoint
assertion, err := signer.Sign(context.Background(), "https://runner-gw.us1.datadog.com")
if err != nil {
    panic(err)
}

// Sample Output: eyJhbGciOiJFUzI1NiIsInR5cCI6ImNsaWVudF9hc3NlcnRpb24rSldUIn0.eyJhdWQiOiJodHRwczovL3J1bm5lci1ndy51czEuZGF0YWRvZy5jb20iLCJleHAiOiIyMDIzLTAyLTIwVDA4OjQ4OjI2LjA0OTA3N1oiLCJpYXQiOiIyMDIzLTAyLTIwVDA4OjQzOjI2LjA0OTA3N1oiLCJpc3MiOiIxMjM0NTY3ODkiLCJqdGkiOiJ1Z0dpazdCbCIsInN1YiI6IjEyMzQ1Njc4OSJ9.wBvOVTLDZeY5UF7Gy5YVxaJvbspLteNZmhHvhIhZTsp5hmNtdKHEljaZyTQuDd0giEsu997ZsG_RLRK4zMI6HQ
fmt.Println(assertion)

```

### type [Verifier](api.go#L27)

`type Verifier interface { ... }`

Verifier describes assertion verifier contract.

#### func [AssertionVerifier](jwt.go#L148)

`func AssertionVerifier(assertionType string, clientKeys ClientKeysResolver, audience string) (Verifier, error)`

AssertionVerifier instantiates a JWT client assertion verifier.

The assertion verifier can verify only one type of assertion, trying to
verify any assertion generated with a different type will raise an error.
The client's public keys are resolved at runtime from the ClientID. This
operation could use caching for performance purpose.
The assertion audience precises the assertion target, trying to verify an
assertion with an audience mismatch will raise a verification error.

To support progressive enhancements, the verification algorithm can support
multiple signature algorithm will the system is migrating to new signature
algorithms. Ensure this list to be as strict as possible.

Authorized by design algorithms are:
* Ed25519 keys => EdDSA
* EC keys => ES256, ES384, ES512
* RSA keys => PS256, PS384, PS512, RS256, RS384, RS512

HMAC (HS*) based are disabled by design due to their lack of identity
authentication ability.

To support clockskew between servers, a default tolerance of 10s is applied
to timestamp verification steps.

```golang
// Decode the key as a JWK
var pk jose.JSONWebKey
if err := json.Unmarshal(clientPrivateJWK, &pk); err != nil {
    panic(err)
}

clientID := "123456789"
audience := "https://runner-gw.us1.datadog.com"

// Create a client assertion signer.
signer, err := AssertionSigner("runner-client", &pk, "123456789", 5*time.Minute)
if err != nil {
    panic(err)
}

// Create client assertion targeting the given endpoint
assertion, err := signer.Sign(context.Background(), audience)
if err != nil {
    panic(err)
}

// Send the ClientID and the assertion to the verifier.

// Create an assertion verifier.
verifier, err := AssertionVerifier("runner-client", func(ctx context.Context, id string) ([]*jose.JSONWebKey, error) {
    // Ensure ClientID format before running any repository-related queries.
    // Use id to lookup the client keys in your repository
    pub := pk.Public()
    return []*jose.JSONWebKey{
        &pub,
    }, nil
}, audience)
if err != nil {
    panic(err)
}

// Verify and authenticate claims.
claims, err := verifier.Verify(context.Background(), clientID, assertion)
if err != nil {
    panic(err)
}
```

 Output:

```
123456789
```

#### func [RestrictedAssertionVerifier](jwt.go#L154)

`func RestrictedAssertionVerifier(assertionType, audience string, opts ...VerifierOption) (Verifier, error)`

RestrictedAssertionVerifier instantiates a JWT client assertion verifier with
a restricted signature algorithm subset.

### type [VerifierOption](jwt.go#L102)

`type VerifierOption func(*verifierOptions)`

VerifierOption allows to customize the JWT verifier.

#### func [WithCAPool](jwt.go#L112)

`func WithCAPool(pool *x509.CertPool) VerifierOption`

WithCAPool allows to specify the CA pool to use to verify the certificate chain

#### func [WithClientKeysResolver](jwt.go#L119)

`func WithClientKeysResolver(resolver ClientKeysResolver) VerifierOption`

WithClientKeysResolver allows to specify the client public keys resolver

#### func [WithSupportedAlgorithms](jwt.go#L105)

`func WithSupportedAlgorithms(algorithms ...jose.SignatureAlgorithm) VerifierOption`

WithSupportedAlgorithms allows to specify the supported signature algorithms

