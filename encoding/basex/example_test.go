package basex

import (
	"fmt"
)

func ExampleEncoding_Encode() {
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

	// Output: =<§%=!^$$$==!<^)!^=>!ùù>ùù^ùù%=%^$ù>$>)
	fmt.Println(b32.Encode(raw))
}
