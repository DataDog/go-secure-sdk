package hashutil

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Vectors from https://www.di-mgt.com.au/sha_testvectors.html
//
//nolint:paralleltest // Parallel testing disabled for vectors
func TestFileHashVector(t *testing.T) {
	root := os.DirFS("./testdata")

	require.NoError(t, fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Ignore directories
		if d.IsDir() {
			return nil
		}

		// Skip non-test files
		if !strings.HasSuffix(path, ".txt") {
			return nil
		}

		t.Run(path, func(t *testing.T) {
			t.Run("sha256", func(t *testing.T) {
				fh, err := root.Open(fmt.Sprintf("%s.sha256", path))
				require.NoError(t, err)
				expected, err := io.ReadAll(hex.NewDecoder(io.LimitReader(fh, maxHashContent)))
				require.NoError(t, err)

				out, err := FileHash(root, path, crypto.SHA256)
				require.NoError(t, err)
				require.Equal(t, expected, out)
			})

			t.Run("sha384", func(t *testing.T) {
				fh, err := root.Open(fmt.Sprintf("%s.sha384", path))
				require.NoError(t, err)
				expected, err := io.ReadAll(hex.NewDecoder(io.LimitReader(fh, maxHashContent)))
				require.NoError(t, err)

				out, err := FileHash(root, path, crypto.SHA384)
				require.NoError(t, err)
				require.Equal(t, expected, out)
			})

			t.Run("sha512", func(t *testing.T) {
				fh, err := root.Open(fmt.Sprintf("%s.sha512", path))
				require.NoError(t, err)
				expected, err := io.ReadAll(hex.NewDecoder(io.LimitReader(fh, maxHashContent)))
				require.NoError(t, err)

				out, err := FileHash(root, path, crypto.SHA512)
				require.NoError(t, err)
				require.Equal(t, expected, out)
			})
		})

		return nil
	}))
}
