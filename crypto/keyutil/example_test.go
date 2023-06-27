// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package keyutil

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/DataDog/go-secure-sdk/generator/randomness"

	"golang.org/x/crypto/pbkdf2"
)

func ExampleToDERBytes() {
	masterPassword := []byte("5gLJpXpXvOUh2gr5lb10zeTwgKWIL0hy0rDPg8B1ncQJ155jPYU7ajrZQPH9HDi")

	// Stretching master passwprd for seed generation
	seed := pbkdf2.Key(masterPassword, []byte("drng-seed-generation"), 4096, 256, sha256.New)

	// Create deterministic random source
	randSource, err := randomness.DRNG(seed, "testing-purpose")
	if err != nil {
		panic(err)
	}

	// Generate an EC key pair
	pub, pk, err := GenerateKeyPairWithRand(randSource, EC)
	if err != nil {
		panic(err)
	}

	var buf bytes.Buffer

	// Encode the private key
	block, raw, err := ToDERBytes(pk)
	if err != nil {
		panic(err)
	}
	if err := pem.Encode(&buf, &pem.Block{
		Type:  block,
		Bytes: raw,
	}); err != nil {
		panic(err)
	}

	// Encode the public key
	block, raw, err = ToDERBytes(pub)
	if err != nil {
		panic(err)
	}
	if err := pem.Encode(&buf, &pem.Block{
		Type:  block,
		Bytes: raw,
	}); err != nil {
		panic(err)
	}

	// Output:
	// -----BEGIN PRIVATE KEY-----
	// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIgX+xyT3F0ACP8BV
	// lIfhA6Q5Q47tFF14bEF9rPAHDRihRANCAAT7jhIdLZPUCWxTe6ctw4BwtNgpSkEx
	// SBlajlxaShtYyubuxY487k6kkLO9rjTODkpXX4pgNvsH85MIPanHXLgR
	// -----END PRIVATE KEY-----
	// -----BEGIN PUBLIC KEY-----
	// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+44SHS2T1AlsU3unLcOAcLTYKUpB
	// MUgZWo5cWkobWMrm7sWOPO5OpJCzva40zg5KV1+KYDb7B/OTCD2px1y4EQ==
	// -----END PUBLIC KEY-----
	fmt.Println(buf.String())
}

func ExamplePublicKeyFingerprint() {
	// Decode certificate
	b, _ := pem.Decode(serverCertPEM)
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(err)
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
