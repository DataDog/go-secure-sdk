package canonicalization

import (
	"encoding/hex"
	"fmt"
)

func ExamplePreAuthenticationEncoding() {
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

	// Output:
	// 00000000  02 00 00 00 00 00 00 00  1c 00 00 00 00 00 00 00  |................|
	// 00000010  64 61 74 61 64 6f 67 2d  65 6e 63 72 79 70 74 69  |datadog-encrypti|
	// 00000020  6f 6e 2d 73 63 68 65 6d  65 2d 76 31 04 00 00 00  |on-scheme-v1....|
	// 00000030  00 00 00 00 01 00 00 00                           |........|
	fmt.Println(hex.Dump(protected))
}
