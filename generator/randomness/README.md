# randomness

Package randomness provides `math/rand` dropin replace with secured initialization.

## Variables

Reader exposes a thread-safe PRNG infinite random bytes generator initialized
with a CSPRNG. Due to its infinite nature, you must ensure a data read limit
in time or space to prevent hanging reader behaviour.

This reader is initialized with a different seed to ensure no collision
between the atomic generation function calls and the stream generator.

```golang
var Reader io.Reader = NewReader(CryptoSeed())
```

## Functions

### func [ASCII](generators.go#L59)

`func ASCII(length int) (string, error)`

ASCII returns a securely generated random ASCII string. It reads random
numbers from crypto/rand and searches for printable characters. It will
return an error if the system's secure random number generator fails to
function correctly, in which case the caller must not continue.

Entropy is 6.5 bits per character.

### func [Alphabet](generators.go#L75)

`func Alphabet(length int) (string, error)`

Alphabet returns a random string of the given length using the 52
alphabetic characters in the POSIX/C locale (a-z+A-Z).

Entropy is 5.7 bits per character.

### func [Alphanumeric](generators.go#L67)

`func Alphanumeric(length int) (string, error)`

Alphanumeric returns a random string of the given length using the 62
alphanumeric characters in the POSIX/C locale (0-9+a-z+A-Z).

Entropy is 5.95 bits per character.

### func [Bytes](generators.go#L25)

`func Bytes(size int) ([]byte, error)`

Bytes generates a new byte slice of the given size.

Entropy is 8 bits per byte.

### func [CryptoSeed](source.go#L11)

`func CryptoSeed() int64`

CryptoSeed returns a seed using crypto/rand. On error, the function generates
a panic with the error.

```golang

// Usign rand.Seed is deprecated since Go 1.20.
// Initialize the concurrent usage safe PRNG math/rand with a CSPRNG sourced random integer.
prng := NewLockedRand(CryptoSeed())

// Generate a random number between 0 and 99
prng.Intn(100)

```

### func [DRNG](csprng_seed.go#L37)

`func DRNG(seed []byte, purpose string) (io.Reader, error)`

DRNG creates an high performance deterministic random number generator derived
from the seed and the purpose.
It encrypts an infinite stream of zero with a key derived from parameters.
The data stream is used as an entropy source by using the indistinguishability
property of AES encryption, which means that the cipher text is considered
as a random string.

This cryptographic RNG is not required to reseed itself and could be used as
a trusted entropy source without delegating the entrpy source to the external
system depending on the adversary model. This is useful when you want to
generate large amount of pseudorandom data without smashing the system with
syscalls to the entropy generator and keep the entropy at a high level.

This implementation is safe to be called from multiple goroutines.

RFC 8937 describes an RNG that hashes another cryptographic RNG's output
with a secret value derived from a long-term key.
[https://www.rfc-editor.org/rfc/rfc8937.html](https://www.rfc-editor.org/rfc/rfc8937.html)

```golang
// This password is sensitive and must be protected as a sensitive secret
masterPassword := []byte(`GnvPu^vA&WrIS8.;|UvYAR2PT8g&HJUL|;}qC3kw\6:R/Gkh2%e^&cs#5el8ak;`)
purpose := "autorotating-envelope-signature-keypair-generation"

// Stretch the masterPassword with the purpose to retrieve a DRNG seed
seed := pbkdf2.Key(masterPassword, []byte(purpose), 4096, drngSeedLength, sha512.New)

// Initialize a DRNG from the master seed and the purpose
drng, err := DRNG(seed, "signature-keypair-for-2023-02-01")
if err != nil {
    panic(err)
}

// Generate a deterministic keypair based on the master seed and the purpose.
// So that you don't have to handle to storage of this crypto materials.
// Imagine something like deterministic daily key rotation without initial
// key exchange, etc.
pub, sk, err := ed25519.GenerateKey(drng)
if err != nil {
    panic(err)
}
```

 Output:

```
pub: 95e5c0f481e71146eef4b4a1d05e3c09294952a48700068dea29f133490b4a90
sk: 14531fe31a69d5de47b9ebb2a187f4dd9f0cb0426151253d0b063b07ecb036c595e5c0f481e71146eef4b4a1d05e3c09294952a48700068dea29f133490b4a90
```

### func [ExpFloat64](global.go#L80)

`func ExpFloat64() float64`

ExpFloat64 returns an exponentially distributed float64 in the range
(0, +math.MaxFloat64] with an exponential distribution whose rate parameter
(lambda) is 1 and whose mean is 1/lambda (1) from the default Source.
To produce a distribution with a different rate parameter,
callers can adjust the output using:

```go
sample = ExpFloat64() / desiredRateParameter
```

### func [Float32](global.go#L52)

`func Float32() float32`

Float32 returns, as a float32, a pseudo-random number in the half-open interval [0.0,1.0)
from the default Source.

### func [Float64](global.go#L48)

`func Float64() float64`

Float64 returns, as a float64, a pseudo-random number in the half-open interval [0.0,1.0)
from the default Source.

### func [Hex](generators.go#L93)

`func Hex(length int) (string, error)`

Hex returns a random string of the given length using the hexadecimal
characters in lower case (0-9+a-f).

Entropy is 4 bits per character.

### func [Int](global.go#L29)

`func Int() int`

Int returns a non-negative pseudo-random int from the default Source.

### func [Int31](global.go#L26)

`func Int31() int32`

Int31 returns a non-negative pseudo-random 31-bit integer as an int32
from the default Source.

### func [Int31n](global.go#L39)

`func Int31n(n int32) int32`

Int31n returns, as an int32, a non-negative pseudo-random number in the half-open interval [0,n)
from the default Source.
It panics if n <= 0.

### func [Int63](global.go#L14)

`func Int63() int64`

Int63 returns a non-negative pseudo-random 63-bit integer as an int64
from the default Source.

### func [Int63n](global.go#L34)

`func Int63n(n int64) int64`

Int63n returns, as an int64, a non-negative pseudo-random number in the half-open interval [0,n)
from the default Source.
It panics if n <= 0.

### func [Intn](global.go#L44)

`func Intn(n int) int`

Intn returns, as an int, a non-negative pseudo-random number in the half-open interval [0,n)
from the default Source.
It panics if n <= 0.

### func [NewReader](global.go#L91)

`func NewReader(seed int64) io.Reader`

NewReader returns an infinite random data generator stream reader.

### func [NormFloat64](global.go#L71)

`func NormFloat64() float64`

NormFloat64 returns a normally distributed float64 in the range
[-math.MaxFloat64, +math.MaxFloat64] with
standard normal distribution (mean = 0, stddev = 1)
from the default Source.
To produce a different normal distribution, callers can
adjust the output using:

```go
sample = NormFloat64() * desiredStdDev + desiredMean
```

### func [Number](generators.go#L101)

`func Number(length int) (string, error)`

Number returns a random string of the given length using the 10
numeric characters in the POSIX/C locale (0-9).

Entropy is 3.32 bits per character.

### func [Perm](global.go#L56)

`func Perm(n int) []int`

Perm returns, as a slice of n ints, a pseudo-random permutation of the integers
in the half-open interval [0,n) from the default Source.

### func [Shuffle](global.go#L61)

`func Shuffle(n int, swap func(i, j int))`

Shuffle pseudo-randomizes the order of elements using the default Source.
n is the number of elements. Shuffle panics if n < 0.
swap swaps the elements with indexes i and j.

### func [String](generators.go#L39)

`func String(length int, chars string) (string, error)`

String returns a random string of a given length using the characters in
the given string. It splits the string on runes to support UTF-8
characters.

Entropy is log2(len(chars)) bits per character.

### func [Uint32](global.go#L18)

`func Uint32() uint32`

Uint32 returns a pseudo-random 32-bit value as a uint32
from the default Source.

### func [Uint64](global.go#L22)

`func Uint64() uint64`

Uint64 returns a pseudo-random 64-bit value as a uint64
from the default Source.

### func [VerificationCode](generators.go#L85)

`func VerificationCode(length int) (string, error)`

VerificationCode returns a random string without vowels and confusing
characters (0, O, 1, l, I). It is useful to prevent word generation and
more precisely offensive words.
It uses the 20 characters in the POSIX/C locale (BCDFGHJKLMNPQRSTVWXYZ).

Entropy is 4.32 bits per character.

## Types

### type [LockedRand](locked_rand.go#L18)

`type LockedRand struct { ... }`

#### func [NewLockedRand](locked_rand.go#L9)

`func NewLockedRand(seed int64) *LockedRand`

NewLockedRand implements a threadsafe wrapper to the math/rand.Rand implementation.

#### func (*LockedRand) [ExpFloat64](locked_rand.go#L143)

`func (lr *LockedRand) ExpFloat64() (n float64)`

ExpFloat64 returns an exponentially distributed float64 in the range
(0, +math.MaxFloat64] with an exponential distribution whose rate parameter
(lambda) is 1 and whose mean is 1/lambda (1).
To produce a distribution with a different rate parameter,
callers can adjust the output using:

```go
sample = ExpFloat64() / desiredRateParameter
```

#### func (*LockedRand) [Float32](locked_rand.go#L107)

`func (lr *LockedRand) Float32() (n float32)`

Float32 returns, as a float32, a pseudo-random number in [0.0,1.0).

#### func (*LockedRand) [Float64](locked_rand.go#L99)

`func (lr *LockedRand) Float64() (n float64)`

Float64 returns, as a float64, a pseudo-random number in [0.0,1.0).

#### func (*LockedRand) [Int](locked_rand.go#L64)

`func (lr *LockedRand) Int() (n int)`

Int returns a non-negative pseudo-random int.

#### func (*LockedRand) [Int31](locked_rand.go#L56)

`func (lr *LockedRand) Int31() (n int32)`

Int31 returns a non-negative pseudo-random 31-bit integer as an int32.

#### func (*LockedRand) [Int31n](locked_rand.go#L82)

`func (lr *LockedRand) Int31n(n int32) (r int32)`

Int31n returns, as an int32, a non-negative pseudo-random number in [0,n).
It panics if n <= 0.

#### func (*LockedRand) [Int63](locked_rand.go#L32)

`func (lr *LockedRand) Int63() (n int64)`

Int63 returns a non-negative pseudo-random 63-bit integer as an int64.

#### func (*LockedRand) [Int63n](locked_rand.go#L73)

`func (lr *LockedRand) Int63n(n int64) (r int64)`

Int63n returns, as an int64, a non-negative pseudo-random number in [0,n).
It panics if n <= 0.

#### func (*LockedRand) [Intn](locked_rand.go#L91)

`func (lr *LockedRand) Intn(n int) (r int)`

Intn returns, as an int, a non-negative pseudo-random number in [0,n).
It panics if n <= 0.

#### func (*LockedRand) [NormFloat64](locked_rand.go#L129)

`func (lr *LockedRand) NormFloat64() (n float64)`

NormFloat64 returns a normally distributed float64 in
the range -math.MaxFloat64 through +math.MaxFloat64 inclusive,
with standard normal distribution (mean = 0, stddev = 1).
To produce a different normal distribution, callers can
adjust the output using:

```go
sample = NormFloat64() * desiredStdDev + desiredMean
```

#### func (*LockedRand) [Perm](locked_rand.go#L115)

`func (lr *LockedRand) Perm(n int) (r []int)`

Perm returns, as a slice of n ints, a pseudo-random permutation of the integers [0,n).

#### func (*LockedRand) [Read](locked_rand.go#L162)

`func (lr *LockedRand) Read(p []byte) (n int, err error)`

Read generates len(p) random bytes and writes them into p. It
always returns len(p) and a nil error.
Read should not be called concurrently with any other Rand method.

#### func (*LockedRand) [Seed](locked_rand.go#L25)

`func (lr *LockedRand) Seed(seed int64)`

Seed uses the provided seed value to initialize the generator to a deterministic state.
Seed should not be called concurrently with any other Rand method.

#### func (*LockedRand) [Shuffle](locked_rand.go#L153)

`func (lr *LockedRand) Shuffle(n int, swap func(i, j int))`

Shuffle pseudo-randomizes the order of elements.
n is the number of elements. Shuffle panics if n < 0.
swap swaps the elements with indexes i and j.

#### func (*LockedRand) [Uint32](locked_rand.go#L40)

`func (lr *LockedRand) Uint32() (n uint32)`

Uint32 returns a pseudo-random 32-bit value as a uint32.

#### func (*LockedRand) [Uint64](locked_rand.go#L48)

`func (lr *LockedRand) Uint64() (n uint64)`

Uint64 returns a pseudo-random 64-bit value as a uint64.

