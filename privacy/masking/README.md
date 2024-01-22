# masking

Package masking provides various data masking used to reduce data value relevance and linkability.

## Introduction

(credits to [https://www.techtarget.com/searchsecurity/tip/Data-masking-vs-data-encryption-How-do-they-differ](https://www.techtarget.com/searchsecurity/tip/Data-masking-vs-data-encryption-How-do-they-differ))

### What is Data Masking

Data masking is the process of turning sensitive data into fake, or masked,
data that looks similar to the authentic data. Masking reveals no genuine
information, making it useless to an attacker if intercepted.

Data masking is challenging. The masked data set needs to maintain the
complexity and unique characteristics of the original unmasked data set so
queries and analysis still yield the same results. This means masked data
must maintain referential integrity across systems and databases.
An individual's Social Security number, for example, must get masked to the
same SSN to preserve primary and foreign keys and relationships.
It's important to note, however, that not every data field needs masking.

### Types of data masking

A variety of data masking techniques can be used to obfuscate data depending
on the type, including the following:

- `Scrambling` randomly orders alphanumeric characters to obscure the
original content.
- `Substitution` replaces the original data with another value, while
preserving the original characteristics of the data.
- `Shuffling` rearranges values within a column, such as user surnames.
- `Date aging` increases or decreases a date field by a specific date range.
- `Variance` applies a variance to number or date fields. It is often used
to mask financial and transaction information.
- `Masking out` scrambles only part of a value. It is commonly applied to
credit card numbers where only the last four digits remain unchanged.
- `Nullifying` replaces the real values with a null value.

The three main types of data masking are the following:
- `Dynamic data masking` is applied in real time to provide role-based security;
for example, returning masked data to a user who does not have the
authority to see the real data.
- `Static data` masking creates a separate masked set of the data that can
be used for research and development.
- `On-the-fly data masking` enables development teams to quickly read and
mask a small subset of production data to use in a test environment.

## Variables

Reference(s):
* [https://support.google.com/analytics/answer/2763052](https://support.google.com/analytics/answer/2763052)
* [https://en.internet.nl/privacy/](https://en.internet.nl/privacy/)

```golang
var (
    IPv4MaskRecommended = 16
    IPv6MaskRecommended = 80
)
```

## Functions

### func [Email](pii.go#L9)

`func Email(value string) (ret string, err error)`

Email default masking method

```golang
out, err := Email("firstname.lastname@datadoghq.com")
if err != nil {
    panic(err)
}
```

 Output:

```
f****************e@d***********m
```

### func [HMAC](hmac.go#L18)

`func HMAC(value string, key []byte) (string, error)`

HMAC generates a HMAC-SHA256 hex encoded output of the given value.

The output is deterministic.

```golang
key := []byte(`]P_Vk0tsK%:7Sq_;iOL.Oc:RQ>OO9B'zkhd<yba_e0V\&*5T1c|B%UH,BBi&Hu.`)

out, err := HMAC("sensitive-data", key)
if err != nil {
    panic(err)
}
```

 Output:

```
vFh87CuJHak1VntcLiLDdI3_OYK8yEFo3AlSx91cHjs
```

### func [IP](ip.go#L23)

`func IP(value string) (string, error)`

IP will mask the given IP address string according to its detected version.
The value is parsed to detect the IP address version.

If the format is already known, consider using the direct IPv4/IPv6 function
which are designed for performance.

```golang
ips := []string{
    "8.8.8.8",
    "2001:db8:3333:4444:5555:6666:7777:8888",
}

var res []string
for _, ip := range ips {
    out, err := IP(ip)
    if err != nil {
        panic(err)
    }

    res = append(res, out)
}
```

 Output:

```
8.8.0.0
2001:db8:3333::
```

### func [IPAddr](ip.go#L47)

`func IPAddr(ip netip.Addr) (string, error)`

IPAddr used the given netip.Addr instance to compute the masked IP address string.
For IPv4, last 16bits are erased. For IPv6, last 80 bits are erased.

```golang
ip, err := netip.ParseAddr("8.8.8.8")
if err != nil {
    panic(err)
}

out, err := IPAddr(ip)
if err != nil {
    panic(err)
}
```

 Output:

```
8.8.0.0
```

### func [IPMask](ip.go#L60)

`func IPMask(ip netip.Addr, mask int) (string, error)`

IPMask is used to compute the prefix of the given IP address and erase last
`mask` bits.

```golang
ip, err := netip.ParseAddr("8.8.8.8")
if err != nil {
    panic(err)
}

out, err := IPMask(ip, 8)
if err != nil {
    panic(err)
}
```

 Output:

```
8.8.8.0
```

### func [IPv4](ip.go#L36)

`func IPv4(value string) (string, error)`

IPv4 assumes the given value to be a string representation of an IPv4 address
and process the string to generate the masked value.

```golang
out, err := IPv4("8.8.8.8")
if err != nil {
    panic(err)
}
```

 Output:

```
8.8.0.0
```

### func [NonDeterministicHMAC](hmac.go#L36)

`func NonDeterministicHMAC(value string, key []byte) (string, error)`

NonDeterministicHMAC generates a HKDF-SHA256 hex encoded output of the given
value. By being non-deterministic, it breaks the linkability between encoded
values, but stays verifiable from the original value computation.

The output is NON deterministic.

```golang

key := []byte(`]P_Vk0tsK%:7Sq_;iOL.Oc:RQ>OO9B'zkhd<yba_e0V\&*5T1c|B%UH,BBi&Hu.`)

out, err := NonDeterministicHMAC("sensitive-data", key)
if err != nil {
    panic(err)
}

// Sample: 6f8da4153a8005f7220b09e5dfdf7f43436a75c403674564abe1b7b2b451c39d98cbccca309b73b6
fmt.Println(out)

```

### func [ReserveLeft](string.go#L40)

`func ReserveLeft(value string, n int, mask string) (ret string, err error)`

ReserveLeft keeps only n first characters from the input string and mask
others with the given mask character.

```golang
out, err := ReserveLeft("Datadog Privacy", 3, "*")
if err != nil {
    panic(err)
}
```

 Output:

```
Dat************
```

### func [ReserveMargin](string.go#L10)

`func ReserveMargin(value string, n int, mask string) (ret string, err error)`

ReserveMargin keeps only n first and last characters from the input string
and mask others with the given mask character.

```golang
out, err := ReserveMargin("Datadog Privacy", 3, "*")
if err != nil {
    panic(err)
}
```

 Output:

```
Dat*********acy
```

### func [ReserveRight](string.go#L66)

`func ReserveRight(value string, n int, mask string) (ret string, err error)`

ReserveRight keeps only n last characters from the input string and mask
others with the given mask character.

```golang
out, err := ReserveRight("Datadog Privacy", 3, "*")
if err != nil {
    panic(err)
}
```

 Output:

```
************acy
```

