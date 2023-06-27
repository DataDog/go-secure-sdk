// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package signature

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
)

func Test_ECDSA_Integration(t *testing.T) {
	t.Parallel()

	curves := map[Algorithm]elliptic.Curve{
		ECDSAP256Signature: elliptic.P256(),
		ECDSAP384Signature: elliptic.P384(),
		ECDSAP521Signature: elliptic.P521(),
	}
	for alg, c := range curves {
		alg := alg
		c := c
		t.Run(c.Params().Name, func(t *testing.T) {
			t.Parallel()

			pk, err := ecdsa.GenerateKey(c, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			s, err := ECDSASigner(pk)
			if err != nil {
				t.Fatal(err)
			}

			v, err := ECDSAVerifier(&pk.PublicKey)
			if err != nil {
				t.Fatal(err)
			}

			msg := []byte("hello world !")

			t.Run("check algorithm", func(t *testing.T) {
				if s.Algorithm() != alg {
					t.Error("algorithm mismatch")
				}
				if v.Algorithm() != alg {
					t.Error("algorithm mismatch")
				}
				if s.Algorithm() != v.Algorithm() {
					t.Error("algorithm mismatch")
				}
			})

			t.Run("sign and verify", func(t *testing.T) {
				sig, err := s.Sign(msg)
				if err != nil {
					t.Error(err)
				}

				if err := v.Verify(msg, sig); err != nil {
					t.Error(err)
				}
			})

			t.Run("verify wrong sig", func(t *testing.T) {
				if err := v.Verify(msg, []byte{}); !errors.Is(err, ErrInvalidSignature) {
					t.Error("invalid signature should raise an error")
				}
			})

			t.Run("public key equality", func(t *testing.T) {
				if !bytes.Equal(s.PublicKey(), v.PublicKey()) {
					t.Error("public key mismatch")
				}
			})
		})
	}
}

func BenchmarkECDSASigner(b *testing.B) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}
	for _, c := range curves {
		b.Run(c.Params().Name, func(b *testing.B) {
			pk, err := ecdsa.GenerateKey(c, rand.Reader)
			if err != nil {
				b.Fatal(err)
			}

			s, err := ECDSASigner(pk)
			if err != nil {
				b.Fatal(err)
			}

			b.Run("1", benchmarkSign(1, s))
			b.Run("32", benchmarkSign(32, s))
			b.Run("64", benchmarkSign(64, s))
			b.Run("1k", benchmarkSign(1024, s))
			b.Run("32k", benchmarkSign(32*1024, s))
			b.Run("64k", benchmarkSign(64*1024, s))
		})
	}
}

func BenchmarkECDSAVerifier(b *testing.B) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}
	for _, c := range curves {
		b.Run(c.Params().Name, func(b *testing.B) {
			pk, err := ecdsa.GenerateKey(c, rand.Reader)
			if err != nil {
				b.Fatal(err)
			}

			s, err := ECDSASigner(pk)
			if err != nil {
				b.Fatal(err)
			}

			v, err := ECDSAVerifier(&pk.PublicKey)
			if err != nil {
				b.Fatal(err)
			}

			b.Run("1", benchmarkVerify(1, s, v))
			b.Run("32", benchmarkVerify(32, s, v))
			b.Run("64", benchmarkVerify(64, s, v))
			b.Run("1k", benchmarkVerify(1024, s, v))
			b.Run("32k", benchmarkVerify(32*1024, s, v))
			b.Run("64k", benchmarkVerify(64*1024, s, v))
		})
	}
}
