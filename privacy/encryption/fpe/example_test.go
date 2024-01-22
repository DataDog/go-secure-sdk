package fpe

import (
	"encoding/hex"
	"fmt"
	"net/netip"
)

func ExampleIP() {
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

	// Output: 6.165.196.67
	fmt.Println(out)
}

func ExampleRegex() {
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

	// Output: 0699-91-7911
	fmt.Println(out)
}
