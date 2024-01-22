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
	"testing"
)

func TestNewFFXKeyLength(t *testing.T) {
	t.Parallel()

	var err error
	var key []byte

	var bad_lengths []int = []int{15, 23, 26, 30, 33, 64}
	var good_lengths []int = []int{16, 24, 32}

	twk := make([]byte, 4)

	for _, len := range bad_lengths {
		key = make([]byte, len)
		_, err = newFFX(key, twk, 1024, 0, 0, "0123456789")
		if err == nil {
			t.FailNow()
		}
	}

	for _, len := range good_lengths {
		key = make([]byte, len)
		_, err = newFFX(key, twk, 1024, 0, 0, "0123456789")
		if err != nil {
			t.Fatal(err)
		}
	}
}
