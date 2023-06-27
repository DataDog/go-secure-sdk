# keyutil

Package keyutil provides cryptographic keys management functions.

This package follows the recommendations provided by the SDG SKB
[Cryptographic security specification]([https://datadoghq.atlassian.net/wiki/spaces/SECENG/pages/2285633911/Cryptographic+security+specification](https://datadoghq.atlassian.net/wiki/spaces/SECENG/pages/2285633911/Cryptographic+security+specification))

## Functions

### func [ExtractKey](generate.go#L146)

`func ExtractKey(in any) (any, error)`

ExtractKey returns the given public or private key or extracts the public key
if a x509.Certificate or x509.CertificateRequest is given.

### func [FromEncryptedJWK](jwk.go#L121)

`func FromEncryptedJWK(r io.Reader, secret []byte) (*jose.JSONWebKey, error)`

FromEncryptedJWK unwraps the JWK encoded in a JWE container encrypted using
AES256GCM with key derivation based on PBES2_HS512_A256KW.

### func [FromJWK](jwk.go#L90)

`func FromJWK(r io.Reader) (*jose.JSONWebKey, error)`

FromJWK tries to decode the given reader content as JWK.

### func [GenerateDefaultKeyPair](generate.go#L53)

`func GenerateDefaultKeyPair() (crypto.PublicKey, crypto.PrivateKey, error)`

GenerateDefaultKeyPair generates a cryptogrpahic key pair according to the
framework enabled flags.

FIPS Mode *enabled* => EC

FIPS Mode *disabled* => OKP (Ed25519)

### func [GenerateKeyPair](generate.go#L63)

`func GenerateKeyPair(kty KeyType) (crypto.PublicKey, crypto.PrivateKey, error)`

GenerateKeyPair generates a key pair according to the selected keytype.

```golang

// Generate EC key pair.
// Use RSA, EC or OKP (Ed25519) as parameter according to your need.
_ /*pub*/, _ /*priv*/, err := GenerateKeyPair(EC)
if err != nil {
    panic(err)
}

```

### func [GenerateKeyPairWithRand](generate.go#L77)

`func GenerateKeyPairWithRand(r io.Reader, kty KeyType) (crypto.PublicKey, crypto.PrivateKey, error)`

GenerateKeyPairWithRand generates a key pair according to the selected keytype
and allow a custom randsource to be used.

FYI, RSA key generation Go implementation can't be deterministic by design.
[https://github.com/golang/go/issues/38548](https://github.com/golang/go/issues/38548)

### func [IsUsable](support.go#L17)

`func IsUsable(key any) error`

IsUsable returns an error if the given key as environmental restrictions.

### func [PublicKey](generate.go#L119)

`func PublicKey(priv any) (crypto.PublicKey, error)`

PublicKey extracts a public key from a private key.

### func [PublicKeyFingerprint](fingerprint.go#L27)

`func PublicKeyFingerprint(key any) ([]byte, error)`

PublicKeyFingerprint generates a public key fingerprint.
[https://www.rfc-editor.org/rfc/rfc6698](https://www.rfc-editor.org/rfc/rfc6698)

This fingerprint algorithm marshal the public key using PKIX ASN.1 to DER
content. The ASN.1 is processed to retrieve the SubjectPublicKey content from
the ASN.1 serialized and compute the SHA256 of the SubjectPublicKey content.

```golang
// Decode certificate
b, _ := pem.Decode(serverCertPEM)
cert, err := x509.ParseCertificate(b.Bytes)
if err != nil {
    panic(err)
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

### func [ToDERBytes](pem.go#L23)

`func ToDERBytes(key any) (string, []byte, error)`

ToDERBytes encodes the given crypto key as a byte array in ASN.1 DER Form.
It returns the PEM block type as string, and the encoded key.

A private key will be serialized using PKCS8.
Supported private types: *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey

A public key will be serialized using PKIX.
Supported public key types: *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey

```golang
masterPassword := []byte("5gLJpXpXvOUh2gr5lb10zeTwgKWIL0hy0rDPg8B1ncQJ155jPYU7ajrZQPH9HDi")

// Stretching master passwprd for seed generation
seed := pbkdf2.Key(masterPassword, []byte("drng-seed-generation"), 4096, 256, sha256.New)

// Create deterministic random source
randSource, err := randomness.DRNG(seed, "testing-purpose")
if err != nil {
    panic(err)
}

// Generate an EC key pair
pub, pk, err := GenerateKeyPairWithRand(randSource, EC)
if err != nil {
    panic(err)
}

var buf bytes.Buffer

// Encode the private key
block, raw, err := ToDERBytes(pk)
if err != nil {
    panic(err)
}
if err := pem.Encode(&buf, &pem.Block{
    Type:  block,
    Bytes: raw,
}); err != nil {
    panic(err)
}

// Encode the public key
block, raw, err = ToDERBytes(pub)
if err != nil {
    panic(err)
}
if err := pem.Encode(&buf, &pem.Block{
    Type:  block,
    Bytes: raw,
}); err != nil {
    panic(err)
}
```

 Output:

```
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIgX+xyT3F0ACP8BV
lIfhA6Q5Q47tFF14bEF9rPAHDRihRANCAAT7jhIdLZPUCWxTe6ctw4BwtNgpSkEx
SBlajlxaShtYyubuxY487k6kkLO9rjTODkpXX4pgNvsH85MIPanHXLgR
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+44SHS2T1AlsU3unLcOAcLTYKUpB
MUgZWo5cWkobWMrm7sWOPO5OpJCzva40zg5KV1+KYDb7B/OTCD2px1y4EQ==
-----END PUBLIC KEY-----
```

### func [ToEncryptedJWK](jwk.go#L48)

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

### func [ToJWK](jwk.go#L23)

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

### func [VerifyPair](generate.go#L172)

`func VerifyPair(pubkey crypto.PublicKey, key crypto.PrivateKey) error`

VerifyPair that the public key matches the given private key.

## Types

### type [KeyType](generate.go#L35)

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

## Sub Packages

* [deterministicecdsa](./deterministicecdsa): Package deterministicecdsa imports the Go 1.19.5 crypto/ecdsa package to keep deterministic key generation for a specific random source.

* [provider](./provider): Package provider provides Key provider contract and standard implementations.

