# canonicalization

Package cryptographically usable canonicalization process.

## Variables

```golang
var (
    // ErrPieceTooLarge is raised when one piece size is larger than the accepted size.
    ErrPieceTooLarge = errors.New("at least one piece is too large")
    // ErrTooManyPieces is raised when the pieces count is larger than the accepted count.
    ErrTooManyPieces = errors.New("too many pieces provided")
)
```

## Functions

### func [PreAuthenticationEncoding](pae.go#L46)

`func PreAuthenticationEncoding(pieces ...[]byte) ([]byte, error)`

PreAuthenticationEncoding implements pre-authenticated-encoding primitive to
encode before MAC or HASH values.
It acts as a normalized canonicalization process.

Canonicalization helps avoid confusion when you have a few separate pieces of
data to hash or encrypt with a single pass. For example, you might want to hash
or sign a string like `userId=1234&userName=megan`.

But the user could change their `userName` to `megan&userRole=admin` and
unexpectedly escalate their privileges when the decoder can't tell which parts
of the data are controlled by the user vs. the code.

Use canonicalization to separate each piece of data so there's no possibility
of confusing the separate pieces.

If you are interested in more knowledge about canonicalization attacks =>
[https://soatok.blog/2021/07/30/canonicalization-attacks-against-macs-and-signatures/](https://soatok.blog/2021/07/30/canonicalization-attacks-against-macs-and-signatures/)

This canonicalization implementation comes from the PASETO specification
described in the following specification.
[https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding)

The canonicalization process accepts :
* 25 piece count maximum or raise an ErrTooManyPiece error if above the threshold
* 64Kb per piece maximum or raise an ErrPieceTooLarge error if above the threshold

```golang
pieces := [][]byte{
    // Use a domain separation string to link the purpose of the canonicalization
    // and the data which is going to be encoded.
    //
    // How to build a good payload for protected content serialization?
    // https://crypto.junod.info/posts/recursive-hash/
    []byte("datadog-encryption-scheme-v1"),
    // Encode the rest of your data
    {0x01, 0x00, 0x00, 0x00},
}

protected, err := PreAuthenticationEncoding(pieces...)
if err != nil {
    panic(err)
}
```

 Output:

```
00000000  02 00 00 00 00 00 00 00  1c 00 00 00 00 00 00 00  |................|
00000010  64 61 74 61 64 6f 67 2d  65 6e 63 72 79 70 74 69  |datadog-encrypti|
00000020  6f 6e 2d 73 63 68 65 6d  65 2d 76 31 04 00 00 00  |on-scheme-v1....|
00000030  00 00 00 00 01 00 00 00                           |........|
```

