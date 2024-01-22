package password

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Parallel()

	pwd := []byte(`x'w53ff&)Bw6P.)WS7~{c$X$%XbCF<&I|l%vQ*Q@|,nUZ+JPT[TEXfzkEfA01Pq`)

	t.Run("Without pepper", func(t *testing.T) {
		t.Run("Default", func(t *testing.T) {
			t.Parallel()

			h, err := New()
			require.NoError(t, err)
			require.NotNil(t, h)

			encoded, err := h.Hash(pwd)
			require.NoError(t, err)
			require.NotEmpty(t, encoded)

			valid, err := h.Verify(encoded, pwd)
			require.NoError(t, err)
			require.True(t, valid)

			valid, err = h.Verify(encoded, []byte("wrong"))
			require.NoError(t, err)
			require.False(t, valid)
		})

		t.Run("FIPS", func(t *testing.T) {
			t.Parallel()

			h, err := New(WithFIPSCompliance())
			require.NoError(t, err)
			require.NotNil(t, h)

			encoded, err := h.Hash(pwd)
			require.NoError(t, err)
			require.NotEmpty(t, encoded)

			valid, err := h.Verify(encoded, pwd)
			require.NoError(t, err)
			require.True(t, valid)

			valid, err = h.Verify(encoded, []byte("wrong"))
			require.NoError(t, err)
			require.False(t, valid)
		})
	})

	t.Run("With pepper", func(t *testing.T) {
		serverPepperSeed := []byte(`pqIuaay0eBymivqgmpY6oJ5szDOKMoIWCAM8vXmWVm9Lwj4xwVymOAjsN0HTeA1`)

		t.Run("Default", func(t *testing.T) {
			t.Parallel()

			h, err := New(
				WithPepper(serverPepperSeed),
			)
			require.NoError(t, err)
			require.NotNil(t, h)

			h2, err := New()
			require.NoError(t, err)
			require.NotNil(t, h2)

			peppered, err := h.Hash(pwd)
			require.NoError(t, err)
			require.NotEmpty(t, peppered)

			valid, err := h.Verify(peppered, pwd)
			require.NoError(t, err)
			require.True(t, valid)

			valid, err = h.Verify(peppered, []byte("wrong"))
			require.NoError(t, err)
			require.False(t, valid)

			encoded, err := h2.Hash(pwd)
			require.NoError(t, err)
			require.NotEmpty(t, encoded)

			valid, err = h.Verify(encoded, pwd)
			require.NoError(t, err)
			require.False(t, valid)
		})

		t.Run("FIPS", func(t *testing.T) {
			t.Parallel()

			h, err := New(
				WithFIPSCompliance(),
				WithPepper(serverPepperSeed),
			)
			require.NoError(t, err)
			require.NotNil(t, h)

			h2, err := New(
				WithFIPSCompliance(),
			)
			require.NoError(t, err)
			require.NotNil(t, h2)

			peppered, err := h.Hash(pwd)
			require.NoError(t, err)
			require.NotEmpty(t, peppered)

			valid, err := h.Verify(peppered, pwd)
			require.NoError(t, err)
			require.True(t, valid)

			valid, err = h.Verify(peppered, []byte("wrong"))
			require.NoError(t, err)
			require.False(t, valid)

			encoded, err := h2.Hash(pwd)
			require.NoError(t, err)
			require.NotEmpty(t, encoded)

			valid, err = h.Verify(encoded, pwd)
			require.NoError(t, err)
			require.False(t, valid)
		})
	})
}
