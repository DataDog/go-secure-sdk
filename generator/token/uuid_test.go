package token

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"golang.org/x/crypto/hkdf"
)

//nolint:paralleltest // Stateful tests
func Test_UUID_Generate(t *testing.T) {
	// Create a deterministic generator
	g := &verifiableUUIDGenerator{
		randReader: hkdf.Expand(sha256.New, []byte("deterministic-nonce-entropy-source-for-testing-purpose"), nil),
		secretKey:  []byte("my-very-secret-key-for-mac"),
		source: func() ([16]byte, error) {
			u, err := uuid.NewRandomFromReader(strings.NewReader("00000-deterministic-uuid-for-testing-purpose"))
			if err != nil {
				return [16]byte{}, fmt.Errorf("unable to generate a random UUIDv4: %w", err)
			}
			return u, nil
		},
	}

	t.Run("first generation", func(t *testing.T) {
		expectedOut := "1sVEx8brJypjLjRZvve28r_Ncn5z2WCGdcnC2lA9ioSFJkQf4BiwuzEEhAC0ZKQ22FMa7uX5DZgtrhpkl6"
		out, err := g.Generate()
		require.NoError(t, err)
		require.Equal(t, expectedOut, out)
	})

	t.Run("second generation", func(t *testing.T) {
		expectedOut := "1sVEx8brJypjLjRZvve28r_Fe1v4h2ab9AcSV91D8AClHamvmIxxWt2lSJvatzDzvP8nF5lC5cLYkUHRzz"
		out, err := g.Generate()
		require.NoError(t, err)
		require.Equal(t, expectedOut, out)
	})

	t.Run("first generation with prefix", func(t *testing.T) {
		expectedOut := "at_1sVEx8brJypjLjRZvve28r_1paeN44l114dnyImf3vnWTe4MYctDUi9HmpONWr17yWkM2SIurDJrs3w7q43"
		out, err := g.Generate(WithTokenPrefix("at"))
		require.NoError(t, err)
		require.Equal(t, expectedOut, out)
	})

	t.Run("second generation with prefix", func(t *testing.T) {
		expectedOut := "et_1sVEx8brJypjLjRZvve28r_bSZB2XaBgxWz9QUBg7Stosw7onVkW7eCVsKEzQkvp3oxaEuUgeOsqiVbdvi"
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

func Test_UUIDGenerate_RandError(t *testing.T) {
	t.Parallel()

	g := &verifiableUUIDGenerator{
		randReader: strings.NewReader(""),
		secretKey:  []byte("my-very-secret-key-for-mac"),
		source: func() ([16]byte, error) {
			u, err := uuid.NewRandomFromReader(strings.NewReader("00001-deterministic-uuid-for-testing-purpose"))
			if err != nil {
				return [16]byte{}, fmt.Errorf("unable to generate a random UUIDv4: %w", err)
			}
			return u, nil
		},
	}

	_, err := g.Generate()
	if err == nil {
		t.Fatal("an error should be raised")
	}
}

func Test_UUIDGenerate_SourceError(t *testing.T) {
	t.Parallel()

	g := &verifiableUUIDGenerator{
		randReader: rand.Reader,
		secretKey:  []byte("my-very-secret-key-for-mac"),
		source: func() ([16]byte, error) {
			return [16]byte{}, errors.New("error")
		},
	}

	_, err := g.Generate()
	if err == nil {
		t.Fatal("an error should be raised")
	}
}

func Test_UUID_Verify(t *testing.T) {
	// Create a deterministic generator
	g := &verifiableUUIDGenerator{
		randReader: strings.NewReader("deterministic-nonce-entropy-source-for-testing-purpose"),
		secretKey:  []byte("my-very-secret-key-for-mac"),
		source: func() ([16]byte, error) {
			u, err := uuid.NewRandomFromReader(strings.NewReader("00002-deterministic-uuid-for-testing-purpose"))
			if err != nil {
				return [16]byte{}, fmt.Errorf("unable to generate a random UUIDv4: %w", err)
			}
			return u, nil
		},
	}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		tkn := "1rEhxXi9mBwmkGpXxD4Njd_wHOKGDkYTeOIHSFgS9ul7cDrVX3ERymo5SfvLQH7HcuSNdpPTy2fAZKEynG"
		if err := g.Verify(tkn); err != nil {
			t.Fatal(err)
		}

		id, err := g.Extract(tkn)
		require.NoError(t, err)
		require.Equal(t, []byte{0x2f, 0x82, 0x82, 0xcb, 0xe2, 0xf9, 0x49, 0x6f, 0xb1, 0x44, 0xc0, 0xaa, 0x4c, 0xed, 0x56, 0xdb}, id)
		_, err = uuid.FromBytes(id)
		require.NoError(t, err)
	})

	t.Run("valid with prefix", func(t *testing.T) {
		t.Parallel()

		tkn := "et_1rEhxXi9mBwmkGpXxD4Njd_F1TuPP5aLrr1OShjyGUkq9YeMXZrZjpnNAkfLorbsinjMDHdtItdsWstkmh"
		if err := g.Verify(tkn); err != nil {
			t.Fatal(err)
		}

		id, err := g.Extract(tkn)
		require.NoError(t, err)
		require.Equal(t, []byte{0x2f, 0x82, 0x82, 0xcb, 0xe2, 0xf9, 0x49, 0x6f, 0xb1, 0x44, 0xc0, 0xaa, 0x4c, 0xed, 0x56, 0xdb}, id)
		_, err = uuid.FromBytes(id)
		require.NoError(t, err)
	})

	t.Run("valid with invalid prefix", func(t *testing.T) {
		t.Parallel()

		tkn := "et__1rEhxXi9mBwmkGpXxD4Njd_F1TuPP5aLrr1OShjyGUkq9YeMXZrZjpnNAkfLorbsinjMDHdtItdsWstkmh"
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

	t.Run("invalid uuid base62", func(t *testing.T) {
		t.Parallel()

		tkn := "1rEhxXi9m-wmkGpXxD4Njd_wHOKGDkYTeOIHSFgS9ul7cDrVX3ERymo5SfvLQH7HcuSNdpPTy2fAZKEynG"
		if err := g.Verify(tkn); err == nil {
			t.Fatal("an error should be raised")
		}
	})

	t.Run("invalid signature base62", func(t *testing.T) {
		t.Parallel()

		tkn := "1rEhxXi9mBwmkGpXxD4Njd_wHOKGDkYTeOIHSFgS9ul7cDrV-3ERymo5SfvLQH7HcuSNdpPTy2fAZKEynG"
		if err := g.Verify(tkn); err == nil {
			t.Fatal("an error should be raised")
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		t.Parallel()

		tkn := "1rEhxXi9mBwmkGpXxD4Njd_wHOKGDkYTeOIHSFgS9ul7cDrVX3ERymo5SfvLQH8KcuSNdpPTy2fAZKEynG"
		if err := g.Verify(tkn); err == nil {
			t.Fatal("an error should be raised")
		}
	})

	t.Run("tampered prefix", func(t *testing.T) {
		t.Parallel()

		tkn := "bad_1rEhxXi9mBwmkGpXxD4Njd_MLdlJaU0J9toBacxSJT3BQFDqhqt1XDKGc3Wo60WGYDKYG3jBkLtD7RK6TT"
		if err := g.Verify(tkn); err == nil {
			t.Fatal("an error should be raised")
		}
	})
}

func Test_UUID_GenerateAndVerify(t *testing.T) {
	t.Parallel()

	g := VerifiableUUIDGenerator(UUIDv4Source(), []byte("very-secret-mac-key"))
	v := VerifiableUUIDVerifier([]byte("very-secret-mac-key"))

	for i := 0; i < 10000; i++ {
		out, err := g.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Verify(out); err != nil {
			t.Log(out)
			t.Fatal(err)
		}
	}
}

func BenchmarkVerifiableUUIDGenerator(b *testing.B) {
	u := uuid.Must(uuid.NewRandom())
	g := VerifiableUUIDGenerator(StaticUUIDSource(u), []byte("very-secret-mac-key"))

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, err := g.Generate()
		require.NoError(b, err)
		b.SetBytes(int64(len(out)))
	}
}

func BenchmarkVerifiableUUIDVerifier(b *testing.B) {
	g := VerifiableUUIDVerifier([]byte("my-very-secret-key-for-mac"))
	tkn := "et_1rEhxXi9mBwmkGpXxD4Njd_F1TuPP5aLrr1OShjyGUkq9YeMXZrZjpnNAkfLorbsinjMDHdtItdsWstkmh"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		require.NoError(b, g.Verify(tkn))
	}
}
