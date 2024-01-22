package d2

import (
	"bytes"
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

type vectorTest struct {
	Operation      string       `json:"@type"`
	Name           string       `json:"name"`
	Key            hexByteSlice `json:"key"`
	Nonce          hexByteSlice `json:"nonce"`
	PlainText      hexByteSlice `json:"plaintext"`
	AdditionalData hexByteSlice `json:"additionalData"`
	CipherText     hexByteSlice `json:"ciphertext"`
	ExpectFail     bool         `json:"expect-fail"`
}

type vectorManifest struct {
	Name  string        `json:"name"`
	Tests []*vectorTest `json:"tests"`
}

//nolint:paralleltest // Disable parallel tests for vector testing
func TestVector(t *testing.T) {
	testDataFs := os.DirFS("./testdata")

	// Open manifest
	mf, err := testDataFs.Open("v2.vector.json")
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
				out, err := encrypt(bytes.NewReader(tc.Nonce), tc.Key, tc.PlainText, tc.AdditionalData)
				if tc.ExpectFail {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					if !bytes.Equal(tc.CipherText, out) {
						t.Errorf("ciphertext error, got %x, expected %x", out, tc.CipherText)
					}
				}
			case "decrypt":
				out, err := decrypt(tc.Key, tc.CipherText, tc.AdditionalData)
				if tc.ExpectFail {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					if !bytes.Equal(tc.PlainText, out) {
						t.Errorf("plaintext error, got %x, expected %x", out, tc.PlainText)
					}
				}
			}
		})
	}
}
