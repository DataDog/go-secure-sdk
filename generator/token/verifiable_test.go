package token

import (
	"crypto/sha256"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"golang.org/x/crypto/hkdf"
)

//nolint:paralleltest // Stateful tests
func Test_Verifiable_Generate(t *testing.T) {
	// Create a deterministic generator
	g := &verifiableRandomGenerator{
		crcTable:   crc32.MakeTable(crc32.Castagnoli),
		randReader: hkdf.Expand(sha256.New, []byte("deterministic-nonce-entropy-source-for-testing-purpose"), nil),
	}

	t.Run("first generation", func(t *testing.T) {
		expectedOut := "0mXKyMzaQg1hGQOJ08IwFYeYLD2X9bHKrI72"
		out, err := g.Generate()
		require.NoError(t, err)
		require.Equal(t, expectedOut, out)
	})

	t.Run("second generation", func(t *testing.T) {
		expectedOut := "0zvIoLTRwWmFKoSTC9ezsdFU7CspIj1TldBF"
		out, err := g.Generate()
		require.NoError(t, err)
		require.Equal(t, expectedOut, out)
	})

	t.Run("first generation with prefix", func(t *testing.T) {
		expectedOut := "et_0AyGfwqbfzK3hOtITjXP3kbQAMRES7AeeF4i"
		out, err := g.Generate(WithTokenPrefix("et"))
		require.NoError(t, err)
		require.Equal(t, expectedOut, out)
	})

	t.Run("second generation with prefix", func(t *testing.T) {
		expectedOut := "et_0E2blUMHAWuOmLziT2qpGkWJq0Eq2HnA01As"
		out, err := g.Generate(WithTokenPrefix("et"))
		require.NoError(t, err)
		require.Equal(t, expectedOut, out)
	})

	t.Run("third generation with bad prefix", func(t *testing.T) {
		out, err := g.Generate(WithTokenPrefix("et _"))
		require.Error(t, err)
		require.Equal(t, "", out)
	})

	t.Run("fourth generation with bad prefix", func(t *testing.T) {
		out, err := g.Generate(WithTokenPrefix("😀_"))
		require.Error(t, err)
		require.Equal(t, "", out)
	})
}

func Test_Verifiable_Verify(t *testing.T) {
	// Create a deterministic generator
	g := &verifiableRandomGenerator{
		crcTable:   crc32.MakeTable(crc32.Castagnoli),
		randReader: hkdf.Expand(sha256.New, []byte("deterministic-nonce-entropy-source-for-testing-purpose"), nil),
	}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		tkn := "07IpDPLTrPzXUf1CQBeqPamn26GPiiqChRA3"
		if err := g.Verify(tkn); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("valid with prefix", func(t *testing.T) {
		t.Parallel()

		tkn := "et_0kYuYe4aAI6DsZDV8GZyfnTUxrRi7bLwG0ew"
		if err := g.Verify(tkn); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("valid with invalid prefix", func(t *testing.T) {
		t.Parallel()

		tkn := "et__0kYuYe4aAI6DsZDV8GZyfnTUxrRi7bLwG0ew"
		if err := g.Verify(tkn); err == nil {
			t.Fatal("an error should be raised")
		}
	})

	t.Run("too short", func(t *testing.T) {
		t.Parallel()

		tkn := "CDLDuzAwMDAtZ"
		if err := g.Verify(tkn); err == nil {
			t.Fatal("an error should be raised")
		}
	})

	t.Run("invalid base62", func(t *testing.T) {
		t.Parallel()

		tkn := "EFycGuBaZvA12c-BZCKleA7oHojnkCtFK5W0"
		if err := g.Verify(tkn); err == nil {
			t.Fatal("an error should be raised")
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		t.Parallel()

		tkn := "07IpDPLTrPzXUf1CQBeqPamn26GPiiqChR11"
		if err := g.Verify(tkn); err == nil {
			t.Fatal("an error should be raised")
		}
	})

	t.Run("regress #1 - long padded value", func(t *testing.T) {
		t.Parallel()

		tkn := "005wMgVPvRTnpnUSVGqGhOUGUEDtScwMjqvD"
		if err := g.Verify(tkn); err != nil {
			t.Fatal(err)
		}
	})
}

func TestVerifiableRandomWithPurpose(t *testing.T) {
	t.Parallel()

	g1 := VerifiableRandomWithPurpose("lost-credential-token")
	g2 := VerifiableRandomWithPurpose("csrf-token")

	t1, err := g1.Generate()
	require.NoError(t, err)
	require.NotEmpty(t, t1)

	t2, err := g2.Generate()
	require.NoError(t, err)
	require.NotEmpty(t, t2)

	t.Run("valid purpose", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, g1.Verify(t1))
		require.NoError(t, g2.Verify(t2))
	})

	t.Run("purpose mismatch", func(t *testing.T) {
		t.Parallel()

		require.ErrorIs(t, g1.Verify(t2), ErrTokenNotAuthenticated)
		require.ErrorIs(t, g2.Verify(t1), ErrTokenNotAuthenticated)
	})
}

func Test_Verifiable_GenerateAndVerify(t *testing.T) {
	t.Parallel()

	g := VerifiableRandom()
	for i := 0; i < 10000; i++ {
		out, err := g.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := g.Verify(out); err != nil {
			t.Log(out)
			t.Fatal(err)
		}
	}
}

func Test_Generate_RandError(t *testing.T) {
	t.Parallel()

	g := &verifiableRandomGenerator{
		randReader: strings.NewReader(""),
	}

	_, err := g.Generate()
	if err == nil {
		t.Fatal("an error should be raised")
	}
}

func BenchmarkVerifiableGenerator(b *testing.B) {
	g := VerifiableRandom()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, _ := g.Generate()
		b.SetBytes(int64(len(out)))
	}
}

func BenchmarkVerifiableVerifier(b *testing.B) {
	g := VerifiableRandom()
	tkn := "07IpDPLTrPzXUf1CQBeqPamn26GPiiqChRA3"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := g.Verify(tkn); err != nil {
			b.Fatal(err)
		}
	}
}
