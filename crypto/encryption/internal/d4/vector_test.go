// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package d4

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

type hexByteSlice []byte

//nolint:wrapcheck // No need to wrap the error
func (m *hexByteSlice) UnmarshalJSON(b []byte) error {
	var data string
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	// Decode hex
	raw, err := hex.DecodeString(data)
	*m = raw
	return err
}

var _ io.Reader = (*zeroReader)(nil)

type zeroReader struct{}

func (dz zeroReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

type vectorTest struct {
	Operation       string       `json:"@type"`
	Name            string       `json:"name"`
	Key             hexByteSlice `json:"key"`
	Nonce           hexByteSlice `json:"nonce"`
	PlainTextLength int64        `json:"plaintext-len"`
	PlainText       hexByteSlice `json:"plaintext"`
	AdditionalData  hexByteSlice `json:"additional-data"`
	CipherTextHash  hexByteSlice `json:"ciphertext-sha256"`
	CipherText      hexByteSlice `json:"ciphertext"`
	ExpectFail      bool         `json:"expect-fail"`
}

type vectorManifest struct {
	Name  string        `json:"name"`
	Tests []*vectorTest `json:"tests"`
}

//nolint:paralleltest // Disable parallel tests for vector testing
func TestVector(t *testing.T) {
	testDataFs := os.DirFS("./testdata")

	// Open manifest
	mf, err := testDataFs.Open("v4.vector.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func(closer io.Closer) {
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}(mf)

	m := &vectorManifest{}
	if err := json.NewDecoder(io.LimitReader(mf, 1<<20)).Decode(m); err != nil {
		t.Fatal(err)
	}

	for _, tc := range m.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			switch tc.Operation {
			case "encrypt":
				var (
					out             bytes.Buffer
					plaintextReader io.Reader
				)

				switch {
				case tc.PlainTextLength > 0:
					plaintextReader = io.LimitReader(&zeroReader{}, tc.PlainTextLength<<20)
				case len(tc.PlainText) >= 0:
					plaintextReader = bytes.NewReader(tc.PlainText)
				}

				err := encrypt(bytes.NewReader(tc.Nonce), tc.Key, plaintextReader, tc.AdditionalData, &out)
				if tc.ExpectFail {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					if len(tc.CipherTextHash) > 0 {
						h := sha256.Sum256(out.Bytes())
						if !bytes.Equal(tc.CipherTextHash, h[:]) {
							t.Errorf("ciphertext sha256 error, got %x, expected %x", h[:], tc.CipherTextHash)
						}
					}
					if len(tc.CipherText) > 0 {
						if !bytes.Equal(tc.CipherText, out.Bytes()) {
							t.Errorf("ciphertext error, got %x, expected %x", out.Bytes(), tc.CipherText)
						}
					}
				}
			case "decrypt":
				var out bytes.Buffer
				err := decrypt(tc.Key, bytes.NewReader(tc.CipherText), tc.AdditionalData, &out)
				if tc.ExpectFail {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					if !bytes.Equal(tc.PlainText, out.Bytes()) {
						t.Errorf("plaintext error, got %x, expected %x", out.Bytes(), tc.PlainText)
					}
				}
			}
		})
	}
}
