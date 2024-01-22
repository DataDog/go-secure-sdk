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
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/DataDog/go-secure-sdk/encoding/basex"
)

// common structure used by fpe algorithms
type ffx struct {
	// aes 128, 192, or 256. depends on key size
	// mode (cbc) is not specified here. that's done
	// when the encryption is actually performed
	block cipher.Block

	radix int
	// minimum and maximum lengths allowed for
	// {plain,cipher}text and tweaks
	len struct {
		txt, twk struct {
			min, max int
		}
	}
	// the default tweak; this is never nil. in
	// the event that nil is specified, this will
	// be an empty (0-byte) slice
	twk []byte

	encoder *basex.Encoding
}

// allocate a new FFX context
// @twk may be nil
// @mintxt is not supplied as it is determined by the radix
func newFFX(key, twk []byte, maxtxt, mintwk, maxtwk int, alphabet string) (*ffx, error) {
	// Try to initialize the encoder
	encoder, err := basex.NewEncoding(alphabet)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize encoder: %w", err)
	}

	// Re-enter the normal flow
	radix := len(alphabet)

	// for both ff1 and ff3-1: radix**minlen >= 1000000
	//
	// therefore:
	//   minlen = ceil(log_radix(1000000))
	//          = ceil(log_10(1000000) / log_10(radix))
	//          = ceil(6 / log_10(radix))
	mintxt := int(math.Ceil(float64(2) / math.Log10(float64(radix))))
	if mintxt < 2 || mintxt > maxtxt {
		return nil, errors.New(
			"unsupported radix/maximum text length combination")
	}

	// default tweak is always non-nil
	if twk == nil {
		twk = make([]byte, 0)
	}

	// make sure tweak length and limits are all compatible
	if mintwk > maxtwk || len(twk) < mintwk ||
		(maxtwk > 0 && len(twk) > maxtwk) {
		return nil, errors.New("invalid tweak length")
	}

	block, err := aes.NewCipher(key)
	if err != nil || block == nil {
		return nil, fmt.Errorf("unable to initialize block cipher: %w", err)
	}

	this := new(ffx)

	this.block = block

	this.radix = radix

	this.len.txt.min = mintxt
	this.len.txt.max = maxtxt

	this.len.twk.min = mintwk
	this.len.twk.max = maxtwk

	this.twk = make([]byte, len(twk))
	copy(this.twk[:], twk[:])

	this.encoder = encoder

	return this, nil
}

// perform an aes-cbc of the input @s (which must be a multiple
// of 16 bytes long), returning only the last block of cipher
// text in @d. @d and @s may be the same slice but may not
// otherwise overlap
func (f *ffx) prf(d, s []byte) error {
	blockSize := f.block.BlockSize()
	mode := cipher.NewCBCEncrypter(
		f.block,
		// IV is always 0's
		[]byte{
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
		})

	for i := 0; i < len(s); i += blockSize {
		mode.CryptBlocks(d, s[i:i+blockSize])
	}

	return nil
}

// perform an aes-ecb encryption of @s, placing the result
// in @d. @d and @s may overlap in any way
func (f *ffx) ciph(d, s []byte) error {
	// prf does cbc, but we're only going to encrypt
	// a single block which is functionally equivalent
	// to ecb
	return f.prf(d, s[0:16])
}

// convert a big integer to a string in the specified radix,
// padding the output to the left with 0's
func (f *ffx) str(i *big.Int, c int) string {
	s := f.encoder.Encode(i.Bytes())
	return strings.Repeat("0", c-len(s)) + s
}

// fill a slice with the specified value
// byte slice and int value mimics the C interface
func memset(s []byte, c int) {
	for i := 0; i < len(s); i++ {
		s[i] = byte(c)
	}
}

// reverse the bytes in a slice. @d and @s may be the
// same slice but may not otherwise overlap
func revb(d, s []byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = s[j], s[i]
	}
}

// reverse a string
func revs(s string) string {
	r := []rune(s)
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
