// Copyright (c) 2021- Ubiq Security, Inc. (https://ubiqsecurity.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package ff3

import (
	"errors"
	"fmt"
	"math"
	"math/big"
)

// Context structure for the FF3-1 FPE algorithm
type FF3_1 struct {
	ctx *ffx
}

// Allocate a new FF3-1 context structure
//
// @key specifies the key for the algorithm, the length of which will
// determine the underlying aes encryption to use.
//
// @twk specifies the default tweak to be used. the tweak must be
// exactly 7 bytes long
//
// @radix species the radix of the input/output data
func NewFF3_1(key, twk []byte, alphabet string) (*FF3_1, error) {
	// ff3-1 uses the reversed value of the given key
	K := make([]byte, len(key))
	revb(K[:], key[:])

	this := new(FF3_1)
	ctx, err := newFFX(K, twk,
		// maxlen for ff3-1:
		// = 2 * log_radix(2**96)
		// = 2 * log_radix(2**48 * 2**48)
		// = 2 * (log_radix(2**48) + log_radix(2**48))
		// = 2 * (2 * log_radix(2**48))
		// = 4 * log_radix(2**48)
		// = 4 * log2(2**48) / log2(radix)
		// = 4 * 48 / log2(radix)
		// = 192 / log2(radix)
		int(float64(192)/math.Log2(float64(len(alphabet)))),
		7, 7,
		alphabet)
	if err != nil {
		return nil, err
	}

	this.ctx = ctx
	return this, nil
}

// encryption and decryption are largely the same and are implemented
// in this single function with differences handled depending on the
// value of the @enc parameter. @X is the input, @T is the tweak,
// and the result is returned
//
// The comments below reference the steps of the algorithm described here:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
func (f *FF3_1) cipher(X string, T []byte, enc bool) (string, error) {
	var A, B, Y string
	var c, m, y *big.Int

	// Step 1
	n := len(X)
	v := n / 2
	u := n - v

	// use the default tweak if none is specified
	if T == nil {
		T = f.ctx.twk
	}

	if n < f.ctx.len.txt.min ||
		n > f.ctx.len.txt.max {
		return "", errors.New("invalid text length")
	} else if len(T) < f.ctx.len.twk.min ||
		(f.ctx.len.twk.max > 0 &&
			len(T) > f.ctx.len.twk.max) {
		return "", errors.New("invalid tweak length")
	}

	c = big.NewInt(0)
	m = big.NewInt(0)
	y = big.NewInt(0)

	P := make([]byte, 16)
	Tw := make([][]byte, 2)

	// Step 2
	if enc {
		A = X[:u]
		B = X[u:]
	} else {
		B = X[:u]
		A = X[u:]
	}

	// Step 3
	Tw[0] = make([]byte, 4)
	copy(Tw[0][0:3], T[0:3])
	Tw[0][3] = T[3] & 0xf0

	Tw[1] = make([]byte, 4)
	copy(Tw[1][0:3], T[4:7])
	Tw[1][3] = (T[3] & 0x0f) << 4

	for i := 0; i < 8; i++ {
		// Step 4i
		W := Tw[0]
		m.SetUint64(uint64(v))

		if (enc && i%2 == 0) ||
			(!enc && i%2 == 1) {
			W = Tw[1]
			m.SetUint64(uint64(u))
		}

		// Step 4ii
		copy(P[:4], W[:4])
		if enc {
			P[3] ^= byte(i)
		} else {
			P[3] ^= byte(7 - i)
		}

		// reverse B and export the numeral string
		// to the underlying byte representation of
		// the integer
		c.SetString(revs(B), f.ctx.radix)
		nb := c.Bytes()
		if 12 <= len(nb) {
			copy(P[4:], nb[:12])
		} else {
			// pad on the left with 0's, if needed
			memset(P[4:len(P)-len(nb)], 0)
			copy(P[len(P)-len(nb):], nb[:])
		}

		// Step 4iii
		revb(P[:], P[:])
		if err := f.ctx.ciph(P[:], P[:]); err != nil {
			return "", fmt.Errorf("unable encrypt the given plaintext: %w", err)
		}
		revb(P[:], P[:])

		// Step 4iv
		y.SetBytes(P[:])

		// Step 4v
		// c = A +/- P
		c.SetString(revs(A), f.ctx.radix)
		if enc {
			c.Add(c, y)
		} else {
			c.Sub(c, y)
		}

		// set y to radix**m
		y.SetUint64(uint64(f.ctx.radix))
		y.Exp(y, m, nil)

		// c = A +/- P mod radix**m
		c.Mod(c, y)

		// Step 4vii
		A = B
		// Step 4vi, 4viii
		B = revs(f.ctx.str(c, int(m.Int64())))
	}

	// Step 5
	if enc {
		Y = A + B
	} else {
		Y = B + A
	}

	return Y, nil
}

// Encrypt a string @X with the tweak @T
//
// @T may be nil, in which case the default tweak will be used
func (f *FF3_1) Encrypt(X string, T []byte) (string, error) {
	return f.cipher(X, T, true)
}

// Decrypt a string @X with the tweak @T
//
// @T may be nil, in which case the default tweak will be used
func (f *FF3_1) Decrypt(X string, T []byte) (string, error) {
	return f.cipher(X, T, false)
}
