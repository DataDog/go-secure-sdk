# keyutil

Package keyutil provides cryptographic keys management functions.

## Functions

### func [AttachCertificateToJWK](jwk.go#L49)

`func AttachCertificateToJWK(jwk *jose.JSONWebKey, cert *x509.Certificate) error`

AttachCertificateToJWK attaches the given certificate to the JWK.

### func [ExtractKey](generate.go#L175)

`func ExtractKey(in any) (any, error)`

ExtractKey returns the given public or private key or extracts the public key
if a x509.Certificate or x509.CertificateRequest is given.

Supported types:

```go
- *rsa.PublicKey / *rsa.PrivateKey
- *ecdsa.PublicKey / *ecdsa.PrivateKey
- ed25519.PublicKey / ed25519.PrivateKey
- *ecdh.PublicKey / *ecdh.PrivateKey
- []byte
- *x509.Certificate
- *x509.CertificateRequest
- ssh.CryptoPublicKey
- *ssh.Certificate
- jose.JSONWebKey / *jose.JSONWebKey
```

If the input is not a supported type, an error is returned.

### func [FromEncryptedJWK](jwk.go#L185)

`func FromEncryptedJWK(r io.Reader, secret []byte) (*jose.JSONWebKey, error)`

FromEncryptedJWK unwraps the JWK encoded in a JWE container encrypted using
AES256GCM with key derivation based on PBES2_HS512_A256KW.

```golang
encryptedJWK := "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJjdHkiOiJhcHBsaWNhdGlvbi9qd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjEyMDAwMCwicDJzIjoiQ2FlVno0dExSZEtKSEozSkFxakdkZyJ9.C_2fwhcpvnmXENVtV_h-ukQ28Yd9-j693MUQURcgPllUCnHO3-lBqw.oV4ZAjaUMr8Su5o7.1aT8dC2WIj8Wq1QlGetvIyIEEvTz79SXjszTvV0WRMfrJEu4VjWjXYjiMmajNaYsqAXWf5C6-P3-Hs8lR-vKZtHqNgafWQKOZM8nJkMkiwQOcMl_Q4EHV6ni7Ss4ZfRGQ_o8R2ONP9Y88_8tFppLMro1xGNQp1pBem_VHPn8787hLVHZHAfTV--rwvyJ3aRe_RePBZ4RSpjf5inGJPDkEOcAVa043iAF75HGwxu3wLkVyC3wKj4iEIyz-uv3OOG-bKkWci7BrCtPGcdSGNVFRWhoc-aJwgaW6NhdZRRvpviskg8fXg.rbwTiWoeXVMAQ5vMIuCUOQ"

// Pack the private key as JWK
jwk, err := FromEncryptedJWK(strings.NewReader(encryptedJWK), []byte("very-secret-password"))
if err != nil {
    panic(err)
}

// Encode the JWK object as JSON
var out bytes.Buffer
if err := json.NewEncoder(&out).Encode(&jwk); err != nil {
    panic(err)
}
```

 Output:

```
{"kty":"EC","kid":"GQGzLJsjUVoKfbK5It-RQkmcJ7zSjPNHDre2htiQKjA","crv":"P-256","x":"4UldbrAX0tKLFvXxQ_er33af7vkmyn8B7K0WE_AuBWM","y":"VxV_08mpjH-jDu46Rl8khkeHu9luR-a9d6jZbLhtL-w","d":"E3IjbKFj-q0Q76lXxyEBG1x-bHuFK4NBTw2DzsvHuig"}
```

### func [FromJWK](jwk.go#L154)

`func FromJWK(r io.Reader) (*jose.JSONWebKey, error)`

FromJWK tries to decode the given reader content as JWK.

### func [FromPEM](pem.go#L104)

`func FromPEM(r io.Reader) (any, error)`

FromPEM opens a cryptographic key packaged in a PEM block.

A private key will be deserialized using PKCS8, PKCS1 (RSA) or SEC1 (EC).
Supported private types: *rsa.PrivateKey, *ecdsa.PrivateKey, *ecdh.PrivateKey,
ed25519.PrivateKey

A public key will be deserialized using PKIX.
Supported public key types: *rsa.PublicKey, *ecdsa.PublicKey, *ecdh.PublicKey,
ed25519.PublicKey

### func [GenerateDefaultKeyPair](generate.go#L52)

`func GenerateDefaultKeyPair() (crypto.PublicKey, crypto.PrivateKey, error)`

GenerateDefaultKeyPair generates a cryptogrpahic key pair according to the
framework enabled flags.

FIPS Mode *enabled* => EC

FIPS Mode *disabled* => OKP (Ed25519)

### func [GenerateKeyPair](generate.go#L68)

`func GenerateKeyPair(kty KeyType) (crypto.PublicKey, crypto.PrivateKey, error)`

GenerateKeyPair generates a key pair according to the selected keytype.
Supported key types are:

```go
- RSA
- EC
- ED25519 (disabled in FIPS mode)
```

If the key type is not supported, an error is returned.

```golang

// Generate EC key pair.
// Use RSA, EC or OKP (Ed25519) as parameter according to your need.
_ /*pub*/, _ /*priv*/, err := GenerateKeyPair(EC)
if err != nil {
    panic(err)
}

```

### func [IsUsable](support.go#L17)

`func IsUsable(key any) error`

IsUsable returns an error if the given key as environmental restrictions.

### func [PublicKey](generate.go#L114)

`func PublicKey(priv any) (crypto.PublicKey, error)`

PublicKey extracts a public key from a private key.

Supported types:

```go
- *rsa.PrivateKey / *rsa.PublicKey
- *ecdsa.PrivateKey / *ecdsa.PublicKey
- ed25519.PrivateKey / ed25519.PublicKey
- *ecdh.PrivateKey / *ecdh.PublicKey
- jose.JSONWebKey / *jose.JSONWebKey
```

If the input is not a supported type, an error is returned.

### func [PublicKeyFingerprint](fingerprint.go#L41)

`func PublicKeyFingerprint(key any) ([]byte, error)`

PublicKeyFingerprint generates a public key fingerprint.
[https://www.rfc-editor.org/rfc/rfc6698](https://www.rfc-editor.org/rfc/rfc6698)

This fingerprint algorithm marshal the public key using PKIX ASN.1 to DER
content. The ASN.1 is processed to retrieve the SubjectPublicKey content from
the ASN.1 serialized and compute the SHA256 of the SubjectPublicKey content.

Supported key types:

```go
- *rsa.PublicKey / *rsa.PrivateKey
- *ecdsa.PublicKey / *ecdsa.PrivateKey
- ed25519.PublicKey / ed25519.PrivateKey
- *ecdh.PublicKey / *ecdh.PrivateKey
- []byte
- *x509.Certificate
- *x509.CertificateRequest
- ssh.CryptoPublicKey
- *ssh.Certificate
- jose.JSONWebKey / *jose.JSONWebKey
```

Unsupported key will return an error.

```golang
// Decode certificate
b, _ := pem.Decode(serverCertPEM)
if b == nil {
    panic("invalid PEM")
}
cert, err := x509.ParseCertificate(b.Bytes)
if err != nil {
    panic(err)
}
if cert == nil {
    panic("invalid certificate")
}

out, err := PublicKeyFingerprint(cert)
if err != nil {
    panic(err)
}
```

 Output:

```
9351dda87a49db2102aef97dec41a58bd6df9245610c87744b39a0ef3d95a060
```

### func [ToDERBytes](pem.go#L32)

`func ToDERBytes(key any) (string, []byte, error)`

ToDERBytes encodes the given crypto key as a byte array in ASN.1 DER Form.
It returns the PEM block type as string, and the encoded key.

A private key will be serialized using PKCS8.
Supported private types: *rsa.PrivateKey, *ecdsa.PrivateKey, *ecdh.PrivateKey,
ed25519.PrivateKey

A public key will be serialized using PKIX.
Supported public key types: *rsa.PublicKey, *ecdsa.PublicKey, *ecdh.PublicKey,
ed25519.PublicKey

### func [ToEncryptedJWK](jwk.go#L112)

`func ToEncryptedJWK(key *jose.JSONWebKey, secret []byte) (string, error)`

ToEncryptedJWK wraps the JWK encoded in a JWE container encrypted using
AES256GCM with key derivation based on PBES2_HS512_A256KW.

```golang

// Generate EC key pair.
// Use RSA, EC or OKP (Ed25519) as parameter according to your need.
_ /*pub*/, priv, err := GenerateKeyPair(EC)
if err != nil {
    panic(err)
}

// Pack the private key as JWK
jwk, err := ToJWK(priv)
if err != nil {
    panic(err)
}

// Encode the JWK object as JSON
jwe, err := ToEncryptedJWK(jwk, []byte("very-secret-password"))
if err != nil {
    panic(err)
}

// Sample Output: eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJjdHkiOiJhcHBsaWNhdGlvbi9qd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjEyMDAwMCwicDJzIjoiQ2FlVno0dExSZEtKSEozSkFxakdkZyJ9.C_2fwhcpvnmXENVtV_h-ukQ28Yd9-j693MUQURcgPllUCnHO3-lBqw.oV4ZAjaUMr8Su5o7.1aT8dC2WIj8Wq1QlGetvIyIEEvTz79SXjszTvV0WRMfrJEu4VjWjXYjiMmajNaYsqAXWf5C6-P3-Hs8lR-vKZtHqNgafWQKOZM8nJkMkiwQOcMl_Q4EHV6ni7Ss4ZfRGQ_o8R2ONP9Y88_8tFppLMro1xGNQp1pBem_VHPn8787hLVHZHAfTV--rwvyJ3aRe_RePBZ4RSpjf5inGJPDkEOcAVa043iAF75HGwxu3wLkVyC3wKj4iEIyz-uv3OOG-bKkWci7BrCtPGcdSGNVFRWhoc-aJwgaW6NhdZRRvpviskg8fXg.rbwTiWoeXVMAQ5vMIuCUOQ
fmt.Printf("%s", jwe)

```

### func [ToJWK](jwk.go#L25)

`func ToJWK(key any) (*jose.JSONWebKey, error)`

ToJWK encodes the given key as JWK.

```golang

// Generate EC key pair.
// Use RSA, EC or OKP (Ed25519) as parameter according to your need.
_ /*pub*/, priv, err := GenerateKeyPair(EC)
if err != nil {
    panic(err)
}

// Pack the private key as JWK
jwk, err := ToJWK(priv)
if err != nil {
    panic(err)
}

// Encode the JWK object as JSON
var out bytes.Buffer
if err := json.NewEncoder(&out).Encode(&jwk); err != nil {
    panic(err)
}

// Sample Output: {"kty":"EC","kid":"PgsdHR9dGMqt2KWUvO4gK0ImyMZbw0aJntGgSXoQgWo","crv":"P-256","x":"kvpM30q2awL9D9IeEi1LfMXsMIoGTCpXshWNOGvVtNE","y":"y2-dLkAWwNlA9GWBfiqkDYRdWNobPle-DZG8sWsMtJg","d":"hoaLiXhGdsPsAw7HWbI1cbBtnGu37uea6AutcqdTVkw"}
fmt.Printf("%s", out.String())

```

### func [ToPEM](pem.go#L72)

`func ToPEM(w io.Writer, key any) error`

ToPEM encodes the given crypto key as a PEM block.

A private key will be serialized using PKCS8.
Supported private types: *rsa.PrivateKey, *ecdsa.PrivateKey, *ecdh.PrivateKey,
ed25519.PrivateKey

A public key will be serialized using PKIX.
Supported public key types: *rsa.PublicKey, *ecdsa.PublicKey, *ecdh.PublicKey,
ed25519.PublicKey

### func [ToPublicJWKS](jwk.go#L82)

`func ToPublicJWKS(keys ...crypto.PublicKey) (*jose.JSONWebKeySet, error)`

ToPublicJWKS encodes the given keyset to a JSONWebKeySet.

### func [VerifyPair](generate.go#L202)

`func VerifyPair(pubkey crypto.PublicKey, key crypto.PrivateKey) error`

VerifyPair that the public key matches the given private key.

### func [VerifyPublicKey](generate.go#L243)

`func VerifyPublicKey(input any, key crypto.PublicKey) error`

VerifyPublicKey verifies that the given public key matches the given input.

## Types

### type [KeyType](generate.go#L34)

`type KeyType uint`

KeyType repesents the key generation strategy

#### Constants

Keeping 0 for PLATFORM preferred key if one day we support FIPS build flag.

```golang
const (
    // ED25519 defines Edwards 25519 key.
    ED25519 KeyType = iota + 1
    // EC defines EC P-256 key.
    EC
    // RSA defines RSA 2048 key.
    RSA
)
```

