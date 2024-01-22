package transformer

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type noopService struct{}

func (s *noopService) Decrypt(ctx context.Context, raw []byte) ([]byte, error) {
	return raw, nil
}

func (s *noopService) Encrypt(ctx context.Context, raw []byte) ([]byte, error) {
	return raw, nil
}

func Test_kmsTransformer_EncodeDecode(t *testing.T) {
	t.Parallel()

	transform := KMS(&noopService{})

	t.Run("empty ciphertext", func(t *testing.T) {
		t.Parallel()

		ciphertext := []byte("")
		out, err := transform.Decode(ciphertext)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("empty plaintext", func(t *testing.T) {
		t.Parallel()

		plaintext := []byte("")

		ciphertext, err := transform.Encode(plaintext)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)

		out, err := transform.Decode(ciphertext)
		require.NoError(t, err)
		require.Equal(t, plaintext, out)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		plaintext := []byte("test")

		ciphertext, err := transform.Encode(plaintext)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)

		out, err := transform.Decode(ciphertext)
		require.NoError(t, err)
		require.Equal(t, plaintext, out)
	})
}
