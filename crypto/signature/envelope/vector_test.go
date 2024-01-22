package envelope

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/crypto/signature"
	v1 "github.com/DataDog/go-secure-sdk/crypto/signature/envelope/internal/v1"
	v2 "github.com/DataDog/go-secure-sdk/crypto/signature/envelope/internal/v2"
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
	Name          string              `json:"name"`
	PublicKeyPem  string              `json:"public-key-pem"`
	PublicKeyID   hexByteSlice        `json:"public-key-id"`
	PrivateKeyPem string              `json:"private-key-pem"`
	Algorithm     signature.Algorithm `json:"algorithm"`
	Content       string              `json:"content"`
	ContentType   string              `json:"content-type"`
	Timestamp     uint64              `json:"timestamp"`
	Nonce         hexByteSlice        `json:"nonce,omitempty"`
	Protected     hexByteSlice        `json:"protected"`
	Signature     hexByteSlice        `json:"signature"`
	ExpectFail    bool                `json:"expect-fail"`
	UnwrapOnly    bool                `json:"unwrap-only"`
}

type vectorManifest struct {
	Name  string        `json:"name"`
	Tests []*vectorTest `json:"tests"`
}

func runVectors(t *testing.T, version uint8, protectedGenerator func(*vectorTest) ([]byte, error)) {
	t.Helper()

	testDataFs := os.DirFS("./testdata")

	// Open manifest
	mf, err := testDataFs.Open(fmt.Sprintf("v%d.vector.json", version))
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
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			// Compute protected (no fail permitted)
			protected, err := protectedGenerator(tc)
			require.NoError(t, err)
			report := cmp.Diff([]byte(tc.Protected), protected)
			require.Empty(t, report, "Protected content doesn't match, expected %x", protected)

			// Create a signer instance
			signer, err := signature.FromPrivateKeyPEM(strings.NewReader(tc.PrivateKeyPem))
			require.NoError(t, err)
			require.NotNil(t, signer)

			// Create a verifier instance
			verifier, err := signature.FromPublicKeyPEM(strings.NewReader(tc.PublicKeyPem))
			require.NoError(t, err)
			require.NotNil(t, verifier)

			// Sign the protected content
			sig, err := signer.Sign(protected)
			require.NoError(t, err)

			// Some signer doesn't produce deterministic signature so signature
			// comparison check is disabled for them
			if !tc.UnwrapOnly {
				// If a signature is provided compare with it
				if len(tc.Signature) > 0 {
					report := cmp.Diff([]byte(tc.Signature), sig)
					require.Empty(t, report, "Signature doesn't match, expected %x", sig)
				}
			}

			// Enable signature verification only if present
			if len(tc.Signature) > 0 {
				// Verify the content
				err = verifier.Verify(tc.Protected, tc.Signature)
				if tc.ExpectFail {
					require.Error(t, err)
				} else {
					require.NoError(t, err, "Expecting success for signature verification with %x", sig)
				}
			}
		})
	}
}

func TestVector(t *testing.T) {
	t.Parallel()

	t.Run("Version 1", func(t *testing.T) {
		t.Parallel()

		//nolint:wrapcheck
		runVectors(t, v1.Version, func(vt *vectorTest) ([]byte, error) {
			return v1.ComputeProtected(vt.Algorithm, vt.Nonce, vt.PublicKeyID, []byte(vt.ContentType), []byte(vt.Content))
		})
	})

	t.Run("Version 2", func(t *testing.T) {
		t.Parallel()

		//nolint:wrapcheck
		runVectors(t, v2.Version, func(vt *vectorTest) ([]byte, error) {
			return v2.ComputeProtected(vt.Algorithm, vt.Timestamp, vt.PublicKeyID, []byte(vt.ContentType), []byte(vt.Content))
		})
	})
}
