// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package randomness

import (
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func testDivergence(t *testing.T, s1 []byte, p1 string, s2 []byte, p2 string) {
	t.Helper()

	drng1, err := DRNG(s1, p1)
	require.NoError(t, err)

	drng2, err := DRNG(s2, p2)
	require.NoError(t, err)

	var buf1, buf2 [512]byte
	_, err = io.ReadFull(drng1, buf1[:])
	require.NoError(t, err)

	_, err = io.ReadFull(drng2, buf2[:])
	require.NoError(t, err)

	require.NotEqual(t, buf1, buf2)
}

func TestDRNG(t *testing.T) {
	t.Parallel()

	seed1, err := Bytes(drngSeedLength)
	require.NoError(t, err)
	seed2, err := Bytes(drngSeedLength)
	require.NoError(t, err)
	require.NotEqual(t, seed1, seed2)

	t.Run("nil seed", func(t *testing.T) {
		t.Parallel()

		drng, err := DRNG(nil, "purpose-1")
		require.Error(t, err)
		require.Nil(t, drng)
	})

	t.Run("nil purpose", func(t *testing.T) {
		t.Parallel()
		testDivergence(t, seed1, "", seed2, "")
	})

	t.Run("same seed/purpose", func(t *testing.T) {
		t.Parallel()
		drng1, err := DRNG(seed1, "purpose-1")
		require.NoError(t, err)

		drng2, err := DRNG(seed1, "purpose-1")
		require.NoError(t, err)

		var buf1, buf2 [512]byte
		_, err = io.ReadFull(drng1, buf1[:])
		require.NoError(t, err)

		_, err = io.ReadFull(drng2, buf2[:])
		require.NoError(t, err)

		require.Equal(t, buf1, buf2)
	})

	t.Run("different purpose", func(t *testing.T) {
		t.Parallel()
		testDivergence(t, seed1, "purpose-1", seed1, "purpose-2")
	})

	t.Run("different seed", func(t *testing.T) {
		t.Parallel()
		testDivergence(t, seed1, "purpose-1", seed2, "purpose-1")
	})

	t.Run("completely different", func(t *testing.T) {
		t.Parallel()
		testDivergence(t, seed1, "purpose-1", seed2, "purpose-2")
	})
}

func BenchmarkDRNGReader(b *testing.B) {
	b.Run("1", benchmarkDRNGReader(1))
	b.Run("512", benchmarkDRNGReader(512))
	b.Run("1024", benchmarkDRNGReader(1024))
	b.Run("2048", benchmarkDRNGReader(2048))
	b.Run("4096", benchmarkDRNGReader(4096))
	b.Run("16384", benchmarkDRNGReader(16384))
	b.Run("32768", benchmarkDRNGReader(32768))
}

//nolint:errcheck
func benchmarkDRNGReader(inputLen int) func(b *testing.B) {
	return func(b *testing.B) {
		b.ReportAllocs()

		seed1, err := Bytes(drngSeedLength)
		require.NoError(b, err)

		drng, err := DRNG(seed1, "testing-purpose")
		require.NoError(b, err)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.SetBytes(int64(inputLen))
			io.CopyN(io.Discard, drng, int64(inputLen))
		}
	}
}

//nolint:errcheck
func TestConcurrentDeterministicReader(t *testing.T) {
	t.Parallel()

	const (
		numRoutines = 10
		numCycles   = 10
	)

	seed1, err := Bytes(drngSeedLength)
	require.NoError(t, err)

	drng1, err := DRNG(seed1, "testing-purpose-1")
	require.NoError(t, err)

	drng2, err := DRNG(seed1, "testing-purpose-2")
	require.NoError(t, err)

	drng3, err := DRNG(seed1, "testing-purpose-3")
	require.NoError(t, err)

	drng4, err := DRNG(seed1, "testing-purpose-4")
	require.NoError(t, err)

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(numRoutines)
	for i := 0; i < numRoutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numCycles; j++ {
				io.CopyN(io.Discard, drng1, 1024)
				io.CopyN(io.Discard, drng2, 1024)
				io.CopyN(io.Discard, drng3, 1024)
				io.CopyN(io.Discard, drng4, 1024)
			}
		}()
	}
}
