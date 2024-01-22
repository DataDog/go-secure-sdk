package encryption

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/crypto/canonicalization"
)

func TestConvergent(t *testing.T) {
	t.Parallel()

	t.Run("Key too large", func(t *testing.T) {
		t.Parallel()

		f, err := Convergent(bytes.Repeat([]byte("A"), maximumKeyLength+1))
		require.Error(t, err)
		require.Nil(t, f)
	})

	t.Run("Seal/Open", func(t *testing.T) {
		t.Parallel()

		f, err := Convergent([]byte("zzTPjjOhqexyMKXAxbelXOZI2lW7VM79kQXEWRPkvMnaWzlJbN1prxEk02huCpD1"))
		require.NoError(t, err)
		require.NotNil(t, f)

		msg := []byte("Hello World!")

		ciphertext, err := f.Seal(msg)
		require.NoError(t, err)
		require.NotNil(t, ciphertext)

		out, err := f.Open(ciphertext)
		require.NoError(t, err)
		require.Equal(t, msg, out)
	})

	t.Run("Seal/Open WithContext", func(t *testing.T) {
		t.Parallel()

		f, err := Convergent([]byte("zzTPjjOhqexyMKXAxbelXOZI2lW7VM79kQXEWRPkvMnaWzlJbN1prxEk02huCpD1"))
		require.NoError(t, err)
		require.NotNil(t, f)

		msg := []byte("Hello World!")

		ciphertext, err := f.SealWithContext(msg, []byte(`{uid:"12345"}`))
		require.NoError(t, err)
		require.NotNil(t, ciphertext)

		out, err := f.OpenWithContext(ciphertext, []byte(`{uid:"12345"}`))
		require.NoError(t, err)
		require.Equal(t, msg, out)
	})

	t.Run("Seal/Open WithContext mismatch", func(t *testing.T) {
		t.Parallel()

		f, err := Convergent([]byte("zzTPjjOhqexyMKXAxbelXOZI2lW7VM79kQXEWRPkvMnaWzlJbN1prxEk02huCpD1"))
		require.NoError(t, err)
		require.NotNil(t, f)

		msg := []byte("Hello World!")

		ciphertext, err := f.SealWithContext(msg, []byte(`{uid:"12345"}`))
		require.NoError(t, err)
		require.NotNil(t, ciphertext)

		out, err := f.OpenWithContext(ciphertext, []byte(`{uid:"987654"}`))
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("Seal WithContext error", func(t *testing.T) {
		t.Parallel()

		f, err := Convergent([]byte("zzTPjjOhqexyMKXAxbelXOZI2lW7VM79kQXEWRPkvMnaWzlJbN1prxEk02huCpD1"))
		require.NoError(t, err)
		require.NotNil(t, f)

		msg := []byte("Hello World!")
		tooLarge := bytes.Repeat([]byte{0x41}, 65*1024) // 65Kb piece

		ciphertext, err := f.SealWithContext(msg, tooLarge)
		require.Error(t, err)
		require.ErrorIs(t, err, canonicalization.ErrPieceTooLarge)
		require.Nil(t, ciphertext)
	})

	t.Run("Open WithContext error", func(t *testing.T) {
		t.Parallel()

		f, err := Convergent([]byte("zzTPjjOhqexyMKXAxbelXOZI2lW7VM79kQXEWRPkvMnaWzlJbN1prxEk02huCpD1"))
		require.NoError(t, err)
		require.NotNil(t, f)

		msg := []byte("Hello World!")
		tooLarge := bytes.Repeat([]byte{0x41}, 65*1024) // 65Kb piece

		ciphertext, err := f.SealWithContext(msg, []byte(`{uid:"12345"}`))
		require.NoError(t, err)
		require.NotNil(t, ciphertext)

		out, err := f.OpenWithContext(ciphertext, tooLarge)
		require.Error(t, err)
		require.ErrorIs(t, err, canonicalization.ErrPieceTooLarge)
		require.Nil(t, out)
	})
}
