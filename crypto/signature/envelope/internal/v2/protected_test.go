// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/crypto/signature"
	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

// TestComputeProtected_Incident18490 ensures that a large payload given to the
// canonicalization is not raising error preventing the signer to generate a
// valid signature.
func TestComputeProtected_Incident18490(t *testing.T) {
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
	hPub := sha256.Sum256(pub)

	// Retrieve signer algorithm identifier
	alg := signer.Algorithm()

	// Try to create protected content.
	out, err := ComputeProtected(alg, uint64(1674656163), hPub[:], []byte("regressionTest"), largeBuffer.Bytes())
	require.NoError(t, err)
	require.Equal(t, []byte{
		0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2d, 0x65, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65,
		0x2d, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2d, 0x76, 0x32, 0x07, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xa4, 0x46, 0xfa, 0x42, 0xf9, 0xcf, 0x00, 0x62, 0xf6, 0x67, 0xbb, 0x63,
		0x65, 0x45, 0x37, 0x3a, 0xe3, 0xb1, 0x10, 0x81, 0x22, 0x4c, 0x7a, 0xf5, 0x20, 0xac, 0xdd, 0xc9,
		0x3f, 0x44, 0xe8, 0x3c, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa3, 0x39, 0xd1, 0x63,
		0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0x0a, 0xfd, 0x94,
		0x14, 0x57, 0xf1, 0x29, 0x0b, 0x2f, 0x31, 0x67, 0x1a, 0x4b, 0x62, 0xf4, 0xea, 0x90, 0x2a, 0xe6,
		0x6c, 0x2e, 0x0d, 0xbe, 0xc1, 0x33, 0x5d, 0x43, 0x61, 0xe9, 0x6c, 0xac,
	}, out)
}

//nolint:errcheck
func BenchmarkComputeProtected(b *testing.B) {
	b.ReportAllocs()

	kid, err := randomness.Bytes(32)
	require.NoError(b, err)

	ts := randomness.Uint64()

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
			ts,
			kid[:],
			[]byte(contentType),
			largeBuffer.Bytes(),
		)
	}
}

//nolint:errcheck
func FuzzComputeProtected(f *testing.F) {
	f.Fuzz(func(t *testing.T, ts uint64, kid, contentType, payload []byte) {
		ComputeProtected(
			signature.ECDSAP256Signature,
			ts,
			kid,
			contentType,
			payload,
		)
	})
}
