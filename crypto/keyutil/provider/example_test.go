// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"crypto/sha512"
	"fmt"

	"github.com/DataDog/go-secure-sdk/crypto/keyutil"
)

func ExampleSymmetricKey_HMAC() {
	// Instantiate a new key provider.
	kp, err := Build(
		WithEntry("production/session/cookie/authentication", StaticSymmetricSecret(
			[]byte("HzglWeYEXABbVDjlxT2qd3L4jLwtNM1wMrJMFevbbtGq87jH5TfscOeCUrPGgpI"),
			SignaturePurpose,
		)),
	)
	if err != nil {
		panic(err)
	}

	// -------------------------------------------------------------------------
	authKey, err := kp.GetSymmetricFor("production/session/cookie/authentication", SignaturePurpose)
	if err != nil {
		panic(err)
	}

	// Initialize a HMAC function with the generated key.
	hm, err := authKey.HMAC(sha512.New)
	if err != nil {
		panic(err)
	}

	// Plain to encrypt
	msg := []byte("Hello world!")

	// Encrypt the plaintext
	hm.Write(msg)

	// Output: 76a02ee7670096ab8a31a200681bee34e8cd74dd56a6ab5692e863d2bbd32a3cd05edc1c124b5c12c3be27689c3cf76aac5e442f7989e8526facfa5409560199
	fmt.Printf("%x", hm.Sum(nil))
}

func ExampleSymmetricKey_ValueEncryption() {
	// Instantiate a new key provider.
	kp := New()

	// Generate a 32bytes secret used for encryption purpose
	encKey, err := kp.GenerateSecret(32, EncryptionPurpose)
	if err != nil {
		panic(err)
	}

	// Initialize Value encryption engine with the generated key.
	aead, err := encKey.ValueEncryption()
	if err != nil {
		panic(err)
	}

	// Plain to encrypt
	msg := []byte("Hello world!")

	// Encrypt the plaintext
	ciphertext, err := aead.Seal(msg)
	if err != nil {
		panic(err)
	}

	// Sample Output: d2229eb4bd1d59c7b03f2d22a687ac50c5874323c8dd49f0d63ca71e3c53195f030f6fdc77d3f9f3fb2bd6f2bd3300d8fc413bf6804914a9e7198bca1900ffb4795efd2886
	fmt.Printf("%x", ciphertext)
}

func ExampleSymmetricKey_DeriveAsymmetric() {
	// Instantiate a new key provider.
	kp := New()

	// Generate a 256bytes secret
	masterSeed, err := kp.GenerateSecret(256, KeyDerivationPurpose)
	if err != nil {
		panic(err)
	}

	// Create a deterministic sub key for signature purpose
	sigPub, sigPriv, err := masterSeed.DeriveAsymmetric(nil, []byte("configuration-signature-v1"), keyutil.EC, SignaturePurpose)
	if err != nil {
		panic(err)
	}

	_ = sigPub
	_ = sigPriv
}
