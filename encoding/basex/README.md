# basex

Package basex provides fast base encoding / decoding of any given alphabet.

It has been copied from github.com/eknkc/basex
Added some preconditions to prevent simple errors.

This library is meant to be used for a given static alphabet, if you are
planning to use common encoding such as Base64, please ensure to use the
dedicated library to support additionnal encoding features (padding, etc.).

## Constants

```golang
const (
    Base2  = "01"
    Base16 = "0123456789abcdef"
    Base32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    Base36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    Base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    Base62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
```

## Types

### type [Encoding](basex.go#L10)

`type Encoding struct { ... }`

Encoding is a custom base encoding defined by an alphabet.
It should be created using NewEncoding function

#### func [NewEncoding](basex.go#L20)

`func NewEncoding(alphabet string) (*Encoding, error)`

NewEncoding returns a custom base encoder defined by the alphabet string.
The alphabet should contain non-repeating characters.
Ordering is important.

#### func (*Encoding) [Decode](basex.go#L86)

`func (e *Encoding) Decode(source string) ([]byte, error)`

Decode function decodes a string previously obtained from Encode, using the same alphabet and returns a byte slice
In case the input is not valid an arror will be returned

#### func (*Encoding) [Encode](basex.go#L46)

`func (e *Encoding) Encode(source []byte) string`

Encode function receives a byte slice and encodes it to a string using the alphabet provided

```golang
// Initialize a custom base encoder
b32, err := NewEncoding(`!)=§$^ù<>%`)
if err != nil {
    panic(err)
}

// Raw value to be encoded
raw := []byte{
    0xce, 0x13, 0x2d, 0x8a, 0x1a, 0x56, 0xe9, 0xe6,
    0xc1, 0x0e, 0x7a, 0x56, 0x2b, 0xda, 0xef, 0xc1,
}
```

 Output:

```
=<§%=!^$$$==!<^)!^=>!ùù>ùù^ùù%=%^$ù>$>)
```

