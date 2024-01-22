# jwt

Package jwt provides external signature mechanism for JWT token signature process.

## Types

### type [Signer](api.go#L11)

`type Signer interface { ... }`

Signer represents the JWT Token signer contract.

#### func [KMSSigner](kmssigner.go#L18)

`func KMSSigner(ctx context.Context, service kms.Service) (Signer, error)`

KMSSigner initalizes a remote KMS signer to be used for JWT signing.

```golang

// Application context
ctx := context.Background()

// Build a Vault client
vc, err := api.NewClient(api.DefaultConfig())
if err != nil {
    panic(err)
}

// Wrap with KMS Service (Raw level operations)
kmsService, err := vault.New(ctx, vc, "transit", "id-token-nonce")
if err != nil {
    // Invalid key / Key not found / etc.
    panic(err)
}

// Wrap service as a JWT signer
tokenSigner, err := KMSSigner(ctx, kmsService)
if err != nil {
    // Public key error / Unsupported key
    panic(err)
}

now := time.Now().UTC()

// Generate a verifiable nonce
nonceGen := token.VerifiableUUIDGenerator(token.UUIDv4Source(), []byte("my-secret-used-to-validate-nonce-generation-without-database-lookup"))
nonce, err := nonceGen.Generate(token.WithTokenPrefix("ddnce"))
if err != nil {
    panic(err)
}

// Compute nonce hash verifier to bind generated nonce and the IDT.
nh := sha256.Sum256([]byte(nonce))
verifier := base64.RawURLEncoding.EncodeToString(nh[:])

// Use the JWT library with remote KMS signer as SigningMethod implementation
t := jwt.New(tokenSigner)
t.Claims = jwt.RegisteredClaims{
    Issuer:  "https://sts.datadoghq.com",
    Subject: "uid:1:123456",
    Audience: jwt.ClaimStrings{
        "mobile-application",
    },
    ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Minute)),
    NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Second)),
    IssuedAt:  jwt.NewNumericDate(now),
    ID:        verifier,
}

// Set explicit token type. (https://datatracker.ietf.org/doc/html/rfc8725#section-3.11)
t.Header["typ"] = "nonce_id_token+jwt"
// Set the public key fingerprint.
t.Header["kid"] = tokenSigner.KeyID()

// Sign the token without specifying the key (it's already managed by the signing method)
token, err := t.SignedString(nil)
if err != nil {
    panic(err)
}

// Get the public key JWK Keyset
publicKeys, err := kmsService.VerificationPublicKeys(ctx)
if err != nil {
    panic(err)
}

// Convert to JWKS.
jwks, err := keyutil.ToPublicJWKS(publicKeys...)
if err != nil {
    panic(err)
}

// Validate JWT token
if _, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
    // Ensure expected headers
    if typ, ok := t.Header["typ"]; ok {
        if typ != "nonce_id_token+jwt" {
            return nil, errors.New("invalid token type")
        }
    } else {
        return nil, errors.New("typ must be defined")
    }

    if kid, ok := t.Header["kid"]; ok {
        // Lookup public key from JWKS
        pub := jwks.Key(kid.(string))
        if len(pub) == 0 {
            return nil, errors.New("invalid public key")
        }

        // Return validation key.
        return pub[0].Key, nil
    }

    return nil, errors.New("kid must be defined")
}, jwt.WithValidMethods([]string{"ES256"})); err != nil {
    panic(err)
}

// Sample Output:
// ddnce_4LQQtRNz44d95VFHBjyiH4_1xghChmpTjp85aloQtZsDpVRVwjfxkivl4Y0sWdakRgfsczGCtSsE7Us2lO1
// eyJhbGciOiJFUzI1NiIsImtpZCI6IjBCc3V3dmU4RDVmMTY4VFd2MXlQaUlrLVFhVFpaVmowWDE3dm51dG5uYlEiLCJ0eXAiOiJub25jZV9pZF90b2tlbitqd3QifQ.eyJpc3MiOiJodHRwczovL3N0cy5kYXRhZG9naHEuY29tIiwic3ViIjoidWlkOjE6MTIzNDU2IiwiYXVkIjpbIm1vYmlsZS1hcHBsaWNhdGlvbiJdLCJleHAiOjE2OTE3NDkxMjYsIm5iZiI6MTY5MTc0OTAwNSwiaWF0IjoxNjkxNzQ5MDA2LCJqdGkiOiJkZG5jZV80TFFRdFJOejQ0ZDk1VkZIQmp5aUg0XzF4Z2hDaG1wVGpwODVhbG9RdFpzRHBWUlZ3amZ4a2l2bDRZMHNXZGFrUmdmc2N6R0N0U3NFN1VzMmxPMSJ9.rPwmtwB3_gbKUQn-8EYLKNaxtWgUqyxQ47RONpQBX5MUNf4qYQUqCO9pq0025VjYbrvoL5tWvZAJb2l3BbNMsw
fmt.Println(nonce)
fmt.Println(token)

```

