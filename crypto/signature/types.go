// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package signature

type Algorithm string

const (
	UnknownSignature   Algorithm = "unknown"
	Ed25519Signature   Algorithm = "ed25519"
	ECDSAP256Signature Algorithm = "ecdsa-p256"
	ECDSAP384Signature Algorithm = "ecdsa-p384"
	ECDSAP521Signature Algorithm = "ecdsa-p521"
)
