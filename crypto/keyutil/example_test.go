// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package keyutil

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

func ExamplePublicKeyFingerprint() {
	// Decode certificate
	b, _ := pem.Decode(serverCertPEM)
	if b == nil {
		panic("invalid PEM")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(err)
	}
	if cert == nil {
		panic("invalid certificate")
	}

	out, err := PublicKeyFingerprint(cert)
	if err != nil {
		panic(err)
	}

	// Output: 9351dda87a49db2102aef97dec41a58bd6df9245610c87744b39a0ef3d95a060
	fmt.Printf("%x", out)
}

func ExampleGenerateKeyPair() {
	// Generate EC key pair.
	// Use RSA, EC or OKP (Ed25519) as parameter according to your need.
	_ /*pub*/, _ /*priv*/, err := GenerateKeyPair(EC)
	if err != nil {
		panic(err)
	}
}

func ExampleToJWK() {
	// Generate EC key pair.
	// Use RSA, EC or OKP (Ed25519) as parameter according to your need.
	_ /*pub*/, priv, err := GenerateKeyPair(EC)
	if err != nil {
		panic(err)
	}

	// Pack the private key as JWK
	jwk, err := ToJWK(priv)
	if err != nil {
		panic(err)
	}

	// Encode the JWK object as JSON
	var out bytes.Buffer
	if err := json.NewEncoder(&out).Encode(&jwk); err != nil {
		panic(err)
	}

	// Sample Output: {"kty":"EC","kid":"PgsdHR9dGMqt2KWUvO4gK0ImyMZbw0aJntGgSXoQgWo","crv":"P-256","x":"kvpM30q2awL9D9IeEi1LfMXsMIoGTCpXshWNOGvVtNE","y":"y2-dLkAWwNlA9GWBfiqkDYRdWNobPle-DZG8sWsMtJg","d":"hoaLiXhGdsPsAw7HWbI1cbBtnGu37uea6AutcqdTVkw"}
	fmt.Printf("%s", out.String())
}

func ExampleToEncryptedJWK() {
	// Generate EC key pair.
	// Use RSA, EC or OKP (Ed25519) as parameter according to your need.
	_ /*pub*/, priv, err := GenerateKeyPair(EC)
	if err != nil {
		panic(err)
	}

	// Pack the private key as JWK
	jwk, err := ToJWK(priv)
	if err != nil {
		panic(err)
	}

	// Encode the JWK object as JSON
	jwe, err := ToEncryptedJWK(jwk, []byte("very-secret-password"))
	if err != nil {
		panic(err)
	}

	// Sample Output: eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJjdHkiOiJhcHBsaWNhdGlvbi9qd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjEyMDAwMCwicDJzIjoiQ2FlVno0dExSZEtKSEozSkFxakdkZyJ9.C_2fwhcpvnmXENVtV_h-ukQ28Yd9-j693MUQURcgPllUCnHO3-lBqw.oV4ZAjaUMr8Su5o7.1aT8dC2WIj8Wq1QlGetvIyIEEvTz79SXjszTvV0WRMfrJEu4VjWjXYjiMmajNaYsqAXWf5C6-P3-Hs8lR-vKZtHqNgafWQKOZM8nJkMkiwQOcMl_Q4EHV6ni7Ss4ZfRGQ_o8R2ONP9Y88_8tFppLMro1xGNQp1pBem_VHPn8787hLVHZHAfTV--rwvyJ3aRe_RePBZ4RSpjf5inGJPDkEOcAVa043iAF75HGwxu3wLkVyC3wKj4iEIyz-uv3OOG-bKkWci7BrCtPGcdSGNVFRWhoc-aJwgaW6NhdZRRvpviskg8fXg.rbwTiWoeXVMAQ5vMIuCUOQ
	fmt.Printf("%s", jwe)
}

func ExampleFromEncryptedJWK() {
	encryptedJWK := "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJjdHkiOiJhcHBsaWNhdGlvbi9qd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjEyMDAwMCwicDJzIjoiQ2FlVno0dExSZEtKSEozSkFxakdkZyJ9.C_2fwhcpvnmXENVtV_h-ukQ28Yd9-j693MUQURcgPllUCnHO3-lBqw.oV4ZAjaUMr8Su5o7.1aT8dC2WIj8Wq1QlGetvIyIEEvTz79SXjszTvV0WRMfrJEu4VjWjXYjiMmajNaYsqAXWf5C6-P3-Hs8lR-vKZtHqNgafWQKOZM8nJkMkiwQOcMl_Q4EHV6ni7Ss4ZfRGQ_o8R2ONP9Y88_8tFppLMro1xGNQp1pBem_VHPn8787hLVHZHAfTV--rwvyJ3aRe_RePBZ4RSpjf5inGJPDkEOcAVa043iAF75HGwxu3wLkVyC3wKj4iEIyz-uv3OOG-bKkWci7BrCtPGcdSGNVFRWhoc-aJwgaW6NhdZRRvpviskg8fXg.rbwTiWoeXVMAQ5vMIuCUOQ"

	// Pack the private key as JWK
	jwk, err := FromEncryptedJWK(strings.NewReader(encryptedJWK), []byte("very-secret-password"))
	if err != nil {
		panic(err)
	}

	// Encode the JWK object as JSON
	var out bytes.Buffer
	if err := json.NewEncoder(&out).Encode(&jwk); err != nil {
		panic(err)
	}

	// Output: {"kty":"EC","kid":"GQGzLJsjUVoKfbK5It-RQkmcJ7zSjPNHDre2htiQKjA","crv":"P-256","x":"4UldbrAX0tKLFvXxQ_er33af7vkmyn8B7K0WE_AuBWM","y":"VxV_08mpjH-jDu46Rl8khkeHu9luR-a9d6jZbLhtL-w","d":"E3IjbKFj-q0Q76lXxyEBG1x-bHuFK4NBTw2DzsvHuig"}
	fmt.Printf("%s", out.String())
}
