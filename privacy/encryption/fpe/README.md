# fpe

Package fpe provides Format Preserving Encryption based helpers.

## Functions

### func [IP](ip.go#L16)

`func IP(key, tweak []byte, ip netip.Addr, operation Operation) (*netip.Addr, error)`

IP uses FF3rev1 from NIST To apply format preserving encryption on the input
netip.Addr object. By providing an IPv4 you will have a matching and reversible
IPv4, same for IPv6 adresses.

```golang
// Key and tweak should be byte arrays. Put your key and tweak here.
// To make it easier for demo purposes, decode from a hex string here.
key, err := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")
if err != nil {
    panic(err)
}
tweak, err := hex.DecodeString("D8E7920AFA330A")
if err != nil {
    panic(err)
}

ipOrig := "89.117.34.1"
ip := netip.MustParseAddr(ipOrig)

out, err := IP(key, tweak, ip, Encrypt)
if err != nil {
    panic(err)
}
```

 Output:

```
6.165.196.67
```

### func [Regex](regex.go#L13)

`func Regex(key, tweak []byte, value, pattern, alphabet string, operation Operation) (string, error)`

Regex pattern applied encryption. This function is used to encrypt part of a string using FF3-1
encryption algorithm.

```golang
// Key and tweak should be byte arrays. Put your key and tweak here.
// To make it easier for demo purposes, decode from a hex string here.
key, err := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")
if err != nil {
    panic(err)
}
tweak, err := hex.DecodeString("D8E7920AFA330A")
if err != nil {
    panic(err)
}

// Define the extraction pattern
ssnPattern := `(\d{4})-(\d{2})-(\d{4})`
// Value to encrypt
ssnValue := `1111-22-3333`
// Alphabet used to decode and reencode the encrypted value
ssnAlphabet := `0123456789`

out, err := Regex(key, tweak, ssnValue, ssnPattern, ssnAlphabet, Encrypt)
if err != nil {
    panic(err)
}
```

 Output:

```
0699-91-7911
```

## Types

### type [Operation](api.go#L3)

`type Operation uint8`

#### Constants

```golang
const (
    Encrypt Operation = iota
    Decrypt
)
```

## Sub Packages

* [ff3](./ff3): Package ff3 provides FF3-1 format preserving encryption primitives.

