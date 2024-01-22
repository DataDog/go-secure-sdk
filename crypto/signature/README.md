# signature

Package signature provides Signature related primitives.

## Variables

ErrInvalidSignature is raised when there is a signature mismatch.

```golang
var ErrInvalidSignature = errors.New("invalid signature")
```

## Types

### type [Algorithm](types.go#L3)

`type Algorithm string`

#### Constants

```golang
const (
    UnknownSignature   Algorithm = "unknown"
    Ed25519Signature   Algorithm = "ed25519"
    ECDSAP256Signature Algorithm = "ecdsa-p256"
    ECDSAP384Signature Algorithm = "ecdsa-p384"
    ECDSAP521Signature Algorithm = "ecdsa-p521"
)
```

### type [KMSOption](kms.go#L142)

`type KMSOption func(*kmsOptions)`

KMSOption describes the functional pattern used for optional settings.

#### func [WithKMSTimeout](kms.go#L149)

`func WithKMSTimeout(d time.Duration) KMSOption`

WithKMSTimeout defines the KMS operation timeout value.

### type [Signer](api.go#L10)

`type Signer interface { ... }`

Signer describes signature producer contract.

#### func [ECDSASigner](ecdsa.go#L15)

`func ECDSASigner(pk *ecdsa.PrivateKey) (Signer, error)`

ECDSASigner returns an ECDSA signer according to the provided private key's curve.

```golang

// Generate an EC keypair
pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
    panic(err)
}

// Wrap the key with an ECDSA signer instance
signer, err := ECDSASigner(pk)
if err != nil {
    panic(err)
}

msg := []byte("Hello World !")

// Sign the message
sig, err := signer.Sign(msg)
if err != nil {
    panic(err)
}

// Create the verifier with the matching public key
verifier, err := ECDSAVerifier(&pk.PublicKey)
if err != nil {
    panic(err)
}

// Verify the message signature.
if err := verifier.Verify(msg, sig); err != nil {
    panic(err)
}

```

#### func [Ed25519Signer](ed25519.go#L13)

`func Ed25519Signer(pk ed25519.PrivateKey) (Signer, error)`

Ed25519Signer instantiates an EdDSA signer using the Ed25519 signature scheme.

Disabled in FIPS Mode.

```golang

// Generate an Ed25519 keypair
pub, pk, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
    panic(err)
}

// Wrap the key with an Ed25519 signer instance
signer, err := Ed25519Signer(pk)
if err != nil {
    panic(err)
}

msg := []byte("Hello World !")

// Sign the message
sig, err := signer.Sign(msg)
if err != nil {
    panic(err)
}

// Create the verifier with the matching public key
verifier, err := Ed25519Verifier(pub)
if err != nil {
    panic(err)
}

// Verify the message signature.
if err := verifier.Verify(msg, sig); err != nil {
    if errors.Is(err, ErrInvalidSignature) {
        // Invalid signature
    }
    panic(err)
}

```

#### func [FromPrivateKey](builder.go#L64)

`func FromPrivateKey(pk crypto.Signer) (Signer, error)`

FromPrivateKey returns the associated signer instance matching the private
key type.

```golang

msg := []byte("...")

// Generate an Ed25519 keypair
_, priv, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
    panic(err)
}

// Use FromPrivateKey to detect the private key type and instantiate the
// appropriate signer.
s, err := FromPrivateKey(priv)
if err != nil {
    panic(err)
}

// Use the signer
sig, err := s.Sign(msg)
if err != nil {
    panic(err)
}

fmt.Println(hex.Dump(append(sig, msg...)))

```

#### func [FromPrivateKeyPEM](builder.go#L77)

`func FromPrivateKeyPEM(r io.Reader) (Signer, error)`

FromPrivateKeyPEM initializes a signer instance from a PEM content.

```golang

msg := []byte("...")
pem := `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCwS7FZqyX0Xbk1hvCp\ngCuVKJL/NjF0B8QCpzWbGCXmPA==
-----END PRIVATE KEY-----`

// Use PrivateKeyFromPEM to decode and detect the private key type and
// instantiate the appropriate signer.
s, err := FromPrivateKeyPEM(strings.NewReader(pem))
if err != nil {
    panic(err)
}

// Use the signer
sig, err := s.Sign(msg)
if err != nil {
    panic(err)
}

fmt.Println(hex.Dump(append(sig, msg...)))

```

#### func [RemoteSigner](kms.go#L21)

`func RemoteSigner(ctx context.Context, remote kms.Service, opts ...KMSOption) (Signer, error)`

RemoteSigner instantiates a signer which will use the remote KMS service as
a private key holder and will send all signature request to this KMS.

### type [Verifier](api.go#L22)

`type Verifier interface { ... }`

Verifier describes signature verifier contract.

#### func [ECDSAVerifier](ecdsa.go#L76)

`func ECDSAVerifier(pub *ecdsa.PublicKey) (Verifier, error)`

#### func [Ed25519Verifier](ed25519.go#L37)

`func Ed25519Verifier(pub ed25519.PublicKey) (Verifier, error)`

Ed25519Verifier instantiates an EdDSA verifier using the Ed25519 signature scheme.

Disabled in FIPS Mode.

#### func [FromPublicKey](builder.go#L16)

`func FromPublicKey(pub crypto.PublicKey) (Verifier, error)`

FromPublicKey returns the associated verifier instance matching the public
key type.

```golang

msg := []byte("...")
sig := []byte("...")

// Generate an Ed25519 keypair
pub, _, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
    panic(err)
}

// Use FromPublicKey to detect the public key type and instantiate the
// appropriate verifier.
v, err := FromPublicKey(pub)
if err != nil {
    panic(err)
}

// Use the verifier
if err := v.Verify(msg, sig); err != nil {
    if errors.Is(err, ErrInvalidSignature) {
        // Invalid signature
    }
    // Other error
}

```

#### func [FromPublicKeyPEM](builder.go#L29)

`func FromPublicKeyPEM(r io.Reader) (Verifier, error)`

FromPublicKeyPEM initializes a verifier instance from a PEM content.

```golang

msg := []byte("...")
sig := []byte("...")
pem := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh4GrAmD45m+8x7VF4W3DjSBxIRVu
zEtcyFbY0FtEDPoZ974Ayk8tWjytNkolc5oCNwHhfQ6QJ4brchPbOgqFOg==
-----END PUBLIC KEY-----`

// Use FromPublicKeyPEM to decode and detect the public key type and
// instantiate the appropriate verifier.
v, err := FromPublicKeyPEM(strings.NewReader(pem))
if err != nil {
    panic(err)
}

// Use the verifier
if err := v.Verify(msg, sig); err != nil {
    if errors.Is(err, ErrInvalidSignature) {
        // Invalid signature
    }
    // Other error
}

```

#### func [RemoteVerifier](kms.go#L122)

`func RemoteVerifier(ctx context.Context, remote kms.PublicKeyExporter) (Verifier, error)`

RemoteVerifier instantiates a local verifier based on the remote public key
stored in Vault. This implementation doesn't handle key rotation, it will
pull automatically the latest version of the target key.

## Sub Packages

* [envelope](./envelope): Package envelope provides Envelope signature scheme.

