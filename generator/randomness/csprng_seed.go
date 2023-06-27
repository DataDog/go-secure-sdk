// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package randomness

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const (
	// drngSeedLength sets the expected DRNG seed length.
	drngSeedLength = 256
)

// DRNG creates an high performance deterministic random number generator derived
// from the seed and the purpose.
// It encrypts an infinite stream of zero with a key derived from parameters.
// The data stream is used as an entropy source by using the indistinguishability
// property of AES encryption, which means that the cipher text is considered
// as a random string.
//
// This cryptographic RNG is not required to reseed itself and could be used as
// a trusted entropy source without delegating the entrpy source to the external
// system depending on the adversary model. This is useful when you want to
// generate large amount of pseudorandom data without smashing the system with
// syscalls to the entropy generator and keep the entropy at a high level.
//
// This implementation is safe to be called from multiple goroutines.
//
// RFC 8937 describes an RNG that hashes another cryptographic RNG's output
// with a secret value derived from a long-term key.
// https://www.rfc-editor.org/rfc/rfc8937.html
func DRNG(seed []byte, purpose string) (io.Reader, error) {
	// Check arguments
	if len(seed) < drngSeedLength {
		return nil, fmt.Errorf("DRNG seed must be at least %d bytes", drngSeedLength)
	}

	// Combine and extract the DRNG key from the given secret and salt
	var rngSeed [32]byte
	kdf := hkdf.New(sha256.New, seed[32:], seed[:32], []byte(purpose))
	if _, err := io.ReadFull(kdf, rngSeed[:]); err != nil {
		return nil, fmt.Errorf("unable to derive drng seed: %w", err)
	}

	// Prepare block cipher with CTR mode
	block, _ := aes.NewCipher(rngSeed[:])
	stream := cipher.NewCTR(block, make([]byte, 16))

	return &streamReader{
		S: stream,
		R: zeroReader{},
	}, nil
}

// -----------------------------------------------------------------------------

var _ io.Reader = (*zeroReader)(nil)

type zeroReader struct{}

func (dz zeroReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// -----------------------------------------------------------------------------

var _ io.Reader = (*streamReader)(nil)

// StreamReader wraps a Stream into an io.Reader. It calls XORKeyStream
// to process each slice of data which passes through.
type streamReader struct {
	mu sync.Mutex
	S  cipher.Stream
	R  io.Reader
}

func (r *streamReader) Read(dst []byte) (n int, err error) {
	r.mu.Lock()
	n, err = r.R.Read(dst)
	r.S.XORKeyStream(dst[:n], dst[:n])
	r.mu.Unlock()

	return
}
