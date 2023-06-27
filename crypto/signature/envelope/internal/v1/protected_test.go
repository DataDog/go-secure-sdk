// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/crypto/signature"
	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

func TestComputeProtected(t *testing.T) {
	t.Parallel()

	// Generate keypair
	pub, priv, err := ed25519.GenerateKey(strings.NewReader("00000-deterministic-key-generation-for-testing"))
	require.NoError(t, err)

	// Create a signer
	signer, err := signature.FromPrivateKey(priv)
	require.NoError(t, err)

	// Generate large payload to sign
	largeBuffer := bytes.Buffer{}

	// Create a 25Mb payload
	_, err = io.Copy(&largeBuffer, io.LimitReader(randomness.NewReader(1), 25<<20))
	require.NoError(t, err)
	require.Equal(t, largeBuffer.Len(), 25<<20)

	// Compute checksums
	hPub := sha512.Sum512_256(pub)

	// Retrieve signer algorithm identifier
	alg := signer.Algorithm()

	// Try to create protected content.
	out, err := ComputeProtected(alg, []byte("12345678"), hPub[:], []byte("regressionTest"), largeBuffer.Bytes())
	require.NoError(t, err)
	require.Equal(t, []byte{
		0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2d, 0x65, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65,
		0x2d, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2d, 0x76, 0x31, 0x00, 0x65, 0x64,
		0x32, 0x35, 0x35, 0x31, 0x39, 0x00, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x6d, 0x63,
		0xad, 0x68, 0x18, 0x7b, 0xc8, 0x8a, 0xf7, 0x73, 0x10, 0xaf, 0xea, 0x81, 0xfb, 0x7a, 0xcc, 0xbd,
		0x0d, 0xb2, 0xa9, 0xa4, 0xb3, 0xa4, 0x4a, 0xec, 0xb0, 0xff, 0x33, 0x2e, 0xb2, 0x31, 0x59, 0x2a,
		0x19, 0x4e, 0x4c, 0xd2, 0x52, 0x78, 0x8b, 0x5c, 0xb7, 0x91, 0xd0, 0x27, 0xf8, 0x38, 0xfd, 0x25,
		0x4c, 0x26, 0x7e, 0xc9, 0xec, 0x6a, 0x93, 0x72, 0x13, 0x1d, 0x0c, 0x3f, 0x21, 0xa9,
	}, out)
}

//nolint:errcheck
func BenchmarkComputeProtected(b *testing.B) {
	b.ReportAllocs()

	kid, err := randomness.Bytes(32)
	require.NoError(b, err)

	contentType, err := randomness.ASCII(255)
	require.NoError(b, err)

	// Generate large payload to sign
	largeBuffer := bytes.Buffer{}

	// Create a 1Mb payload
	_, err = io.Copy(&largeBuffer, io.LimitReader(randomness.NewReader(1), 1<<20))
	require.NoError(b, err)
	require.Equal(b, largeBuffer.Len(), 1<<20)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeProtected(
			signature.ECDSAP256Signature,
			[]byte("0123456789"),
			kid[:],
			[]byte(contentType),
			largeBuffer.Bytes(),
		)
	}
}

//nolint:errcheck
func FuzzComputeProtected(f *testing.F) {
	f.Fuzz(func(t *testing.T, nonce, kid, contentType, payload []byte) {
		ComputeProtected(
			signature.ECDSAP256Signature,
			nonce,
			kid,
			contentType,
			payload,
		)
	})
}
