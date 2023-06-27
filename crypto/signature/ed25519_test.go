// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package signature

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	security "github.com/DataDog/go-secure-sdk"
	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

func Test_ed25519_InvalidKeys(t *testing.T) {
	t.Run("invalid private key length", func(t *testing.T) {
		t.Parallel()

		s, err := Ed25519Signer(ed25519.PrivateKey([]byte("")))
		if err == nil {
			t.Error("error should not be nil")
		}
		if s != nil {
			t.Error("signer should be nil")
		}
	})

	t.Run("invalid public key length", func(t *testing.T) {
		t.Parallel()

		s, err := Ed25519Verifier(ed25519.PublicKey([]byte("")))
		if err == nil {
			t.Error("error should not be nil")
		}
		if s != nil {
			t.Error("verifier should be nil")
		}
	})

	t.Run("invalid signature: public key mismatch", func(t *testing.T) {
		t.Parallel()

		// Sign
		_, priv1, _ := ed25519.GenerateKey(strings.NewReader("00000-deterministic-key-for-testing-purpose"))
		s, err := Ed25519Signer(priv1)
		if err != nil {
			t.Errorf("error should be nil, got %v", err)
		}
		if s == nil {
			t.Error("signer should be nil")
		}

		sig, err := s.Sign([]byte("test"))
		if err != nil {
			t.Errorf("error should be nil, got %v", err)
		}
		if sig == nil {
			t.Error("signature should not be nil")
		}

		// Verify
		pub2, _, _ := ed25519.GenerateKey(strings.NewReader("99999-deterministic-key-for-testing-purpose"))
		v, err := Ed25519Verifier(pub2)
		if err != nil {
			t.Errorf("error should be nil, got %v", err)
		}
		if v == nil {
			t.Error("verifier should not be nil")
		}

		if err := v.Verify([]byte("test"), sig); !errors.Is(err, ErrInvalidSignature) {
			t.Error("invalid signture should raise an error")
		}
	})
}

func Test_Ed25519_Integration(t *testing.T) {
	pub, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s, err := Ed25519Signer(pk)
	if err != nil {
		t.Fatal(err)
	}

	v, err := Ed25519Verifier(pub)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello world !")

	t.Run("check algorithm", func(t *testing.T) {
		t.Parallel()

		if s.Algorithm() != Ed25519Signature {
			t.Error("algorithm mismatch")
		}
		if v.Algorithm() != Ed25519Signature {
			t.Error("algorithm mismatch")
		}
		if s.Algorithm() != v.Algorithm() {
			t.Error("algorithm mismatch")
		}
	})

	t.Run("sign and verify", func(t *testing.T) {
		t.Parallel()

		sig, err := s.Sign(msg)
		if err != nil {
			t.Error(err)
		}

		if err := v.Verify(msg, sig); err != nil {
			t.Error(err)
		}
	})

	t.Run("verify wrong sig", func(t *testing.T) {
		t.Parallel()

		if err := v.Verify(msg, []byte{}); !errors.Is(err, ErrInvalidSignature) {
			t.Error("invalid signature should raise an error")
		}
	})

	t.Run("public key equality", func(t *testing.T) {
		t.Parallel()

		if !bytes.Equal(s.PublicKey(), v.PublicKey()) {
			t.Error("public key mismatch")
		}
	})
}

//nolint:paralleltest // Disable parallel testing due to the stateful nature of the FIPS flag
func Test_Ed25519_FIPSMode(t *testing.T) {
	revertFunc := security.SetFIPSMode()
	require.True(t, security.InFIPSMode())
	defer revertFunc()

	pub, pk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	s, err := Ed25519Signer(pk)
	require.Error(t, err)
	require.Nil(t, s)

	v, err := Ed25519Verifier(pub)
	require.Error(t, err)
	require.Nil(t, v)
}

func BenchmarkEd25519Signer(b *testing.B) {
	_, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	s, err := Ed25519Signer(pk)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("1", benchmarkSign(1, s))
	b.Run("32", benchmarkSign(32, s))
	b.Run("64", benchmarkSign(64, s))
	b.Run("1k", benchmarkSign(1024, s))
	b.Run("32k", benchmarkSign(32*1024, s))
	b.Run("64k", benchmarkSign(64*1024, s))
}

func benchmarkSign(inputLen int, s Signer) func(*testing.B) {
	return func(b *testing.B) {
		b.ReportAllocs()

		buf := &bytes.Buffer{}
		_, err := io.CopyN(buf, randomness.Reader, int64(inputLen))
		require.NoError(b, err)
		msg := buf.Bytes()

		// Ensure good execution first
		sig, err := s.Sign(msg)
		require.NoError(b, err)
		require.NotEmpty(b, sig)

		for i := 0; i < b.N; i++ {
			b.SetBytes(int64(inputLen))
			//nolint:errcheck // Disabled for performance measure
			s.Sign(msg)
		}
	}
}

func BenchmarkEd25519Verifier(b *testing.B) {
	pub, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	s, err := Ed25519Signer(pk)
	if err != nil {
		b.Fatal(err)
	}

	v, err := Ed25519Verifier(pub)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("1", benchmarkVerify(1, s, v))
	b.Run("32", benchmarkVerify(32, s, v))
	b.Run("64", benchmarkVerify(64, s, v))
	b.Run("1k", benchmarkVerify(1024, s, v))
	b.Run("32k", benchmarkVerify(32*1024, s, v))
	b.Run("64k", benchmarkVerify(64*1024, s, v))
}

func benchmarkVerify(inputLen int, s Signer, v Verifier) func(*testing.B) {
	return func(b *testing.B) {
		b.ReportAllocs()

		buf := &bytes.Buffer{}
		_, err := io.CopyN(buf, randomness.Reader, int64(inputLen))
		require.NoError(b, err)
		msg := buf.Bytes()

		sig, err := s.Sign(msg)
		require.NoError(b, err)
		require.NotEmpty(b, sig)

		// Ensure good execution first
		err = v.Verify(msg, sig)
		require.NoError(b, err)

		for i := 0; i < b.N; i++ {
			b.SetBytes(int64(inputLen))
			//nolint:errcheck // Disabled for performance measure
			v.Verify(msg, sig)
		}
	}
}
