# hpke

Package hpke provides RFC9180 hybrid public key encryption features.

## Types

### type [AEAD](api.go#L147)

`type AEAD uint16`

#### Constants

```golang
const (
    // AEAD_AES128GCM is AES-128 block cipher in Galois Counter Mode (GCM).
    AEAD_AES128GCM AEAD = 0x01
    // AEAD_AES256GCM is AES-256 block cipher in Galois Counter Mode (GCM).
    AEAD_AES256GCM AEAD = 0x02
    // AEAD_ChaCha20Poly1305 is ChaCha20 stream cipher and Poly1305 MAC.
    AEAD_ChaCha20Poly1305 AEAD = 0x03
    // AEAD_EXPORT_ONLY is reserved for applications that only use the Exporter
    // interface.
    AEAD_EXPORT_ONLY AEAD = 0xFFFF
)
```

#### func (AEAD) [IsValid](api.go#L162)

`func (a AEAD) IsValid() bool`

#### func (AEAD) [KeySize](api.go#L188)

`func (a AEAD) KeySize() uint16`

#### func (AEAD) [New](api.go#L171)

`func (a AEAD) New(key []byte) (cipher.AEAD, error)`

#### func (AEAD) [NonceSize](api.go#L203)

`func (a AEAD) NonceSize() uint16`

### type [Exporter](keyschedule.go#L18)

`type Exporter interface { ... }`

Exporter describes key derivation operation.

### type [KDF](api.go#L74)

`type KDF uint16`

#### Constants

```golang
const (
    // KDF_HKDF_SHA256 is a KDF using HKDF with SHA-256.
    KDF_HKDF_SHA256 KDF = 0x01
    // KDF_HKDF_SHA384 is a KDF using HKDF with SHA-384.
    KDF_HKDF_SHA384 KDF = 0x02
    // KDF_HKDF_SHA512 is a KDF using HKDF with SHA-512.
    KDF_HKDF_SHA512 KDF = 0x03
)
```

#### func (KDF) [Expand](api.go#L112)

`func (k KDF) Expand(prk, labeledInfo []byte, outputLen uint16) ([]byte, error)`

#### func (KDF) [Extract](api.go#L108)

`func (k KDF) Extract(secret, salt []byte) []byte`

#### func (KDF) [ExtractSize](api.go#L95)

`func (k KDF) ExtractSize() uint16`

#### func (KDF) [IsValid](api.go#L86)

`func (k KDF) IsValid() bool`

### type [KEM](api.go#L32)

`type KEM uint16`

#### Constants

```golang
const (
    // KEM_P256_HKDF_SHA256 is a KEM using P-256 curve and HKDF with SHA-256.
    KEM_P256_HKDF_SHA256 KEM = 0x10
    // KEM_P384_HKDF_SHA384 is a KEM using P-384 curve and HKDF with SHA-384.
    KEM_P384_HKDF_SHA384 KEM = 0x11
    // KEM_P521_HKDF_SHA512 is a KEM using P-521 curve and HKDF with SHA-512.
    KEM_P521_HKDF_SHA512 KEM = 0x12
    // KEM_X25519_HKDF_SHA256 is a KEM using X25519 Diffie-Hellman function
    // and HKDF with SHA-256.
    KEM_X25519_HKDF_SHA256 KEM = 0x20
)
```

#### func (KEM) [IsValid](api.go#L62)

`func (k KEM) IsValid() bool`

#### func (KEM) [Scheme](api.go#L47)

`func (k KEM) Scheme() kem.Scheme`

### type [Opener](receiver.go#L21)

`type Opener interface { ... }`

Opener decrypts a ciphertext using an AEAD encryption.

### type [Receiver](receiver.go#L13)

`type Receiver interface { ... }`

Receiver describes message receiver contract.

### type [Sealer](sender.go#L23)

`type Sealer interface { ... }`

Sealer encrypts a plaintext using an AEAD encryption.

### type [Sender](sender.go#L15)

`type Sender interface { ... }`

Sender describes message sender contract.

### type [Suite](suite.go#L11)

`type Suite interface { ... }`

Suite repesents a HPKE cipher suite contract.

#### func [New](suite.go#L20)

`func New(kemID KEM, kdfID KDF, aeadID AEAD) Suite`

New initializes a new HPKE suite.

