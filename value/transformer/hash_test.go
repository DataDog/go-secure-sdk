package transformer

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_hashTransformer_EncodeDecode(t *testing.T) {
	t.Parallel()

	msg := []byte("test")

	t.Run("nil hasher", func(t *testing.T) {
		t.Parallel()

		transform := Hash(func() hash.Hash { return nil })
		out, err := transform.Encode(msg)
		require.Error(t, err)
		require.ErrorContains(t, err, "hash builder function returned a nil instance")
		require.Nil(t, out)
	})

	t.Run("decode error", func(t *testing.T) {
		t.Parallel()

		transform := Hash(sha256.New)
		out, err := transform.Decode(msg)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrImpossibleOperation)
		require.Nil(t, out)
	})

	t.Run("valid - hmac", func(t *testing.T) {
		t.Parallel()

		transform := Hash(func() hash.Hash {
			return hmac.New(sha256.New, []byte("this is a testing purpose key"))
		})
		out, err := transform.Encode(msg)
		require.NoError(t, err)
		require.Equal(t, []byte{0xb1, 0x14, 0x9c, 0xee, 0x43, 0xc1, 0x19, 0x5d, 0xb2, 0xfc, 0x66, 0x53, 0xd8, 0xe1, 0xc6, 0x30, 0x2, 0x57, 0x42, 0xdb, 0xb8, 0xcf, 0x1, 0x9a, 0x3a, 0x92, 0xcf, 0xbd, 0xbf, 0x29, 0xc0, 0x74}, out)
	})

	t.Run("valid - sha256", func(t *testing.T) {
		t.Parallel()

		transform := Hash(sha256.New)
		out, err := transform.Encode(msg)
		require.NoError(t, err)
		require.Equal(t, []byte{0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0xb, 0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0xa, 0x8}, out)
	})
}
