package certutil

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func ExampleFingerprint() {
	// Decode certificate
	b, _ := pem.Decode(serverCertPEM)
	if b == nil {
		panic("invalid PEM")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(err)
	}

	out, err := Fingerprint(cert)
	if err != nil {
		panic(err)
	}

	// Output: 13f013ba27522762e76a7421a2089c407a476cef8750f8a231fa736e9bb4bf55
	fmt.Printf("%x", out)
}
