// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package d5 provides FIPS compliant deterministic encryption system
//
// Convergent encryption, also known as content hash keying, is a cryptosystem
// that produces identical ciphertext from identical plaintext files.
// To accomplish this, the encryption system is implemented by removing the
// indistinguishability (IND) property of a classic encryption system.
//
// Hence this algorithm must be used with plain knowledge of its usage
// consequences.
//
// > Consider migrating to AES-GCM-SIV once integrated in Go runtime - https://github.com/golang/go/issues/54364.
//
// ## Algorithm
//
// ```ruby
// encKey := HKDF(SHA256, secret, "datadog-convergent-encryption-key-v1")
// nonceKey := HKDF(SHA256, secret, "datadog-convergent-encryption-nonce-v1")
// nonce := HMAC(SHA256, nonceKey, message)
// encrypted := AEAD_ENCRYPT(encKey, nonce, message)
//
// final := nonce || encrypted
//
// decKey := HKDF(SHA256, secret, "datadog-convergent-encryption-key-v1")
// plaintext := AEAD_DECRYPT(decKey, nonce, encrypted)
// ```
//
// ## Additional References
//
// * [Attacks on Convergent Encryption](https://tahoe-lafs.org/hacktahoelafs/drew_perttula.html)
package d5
