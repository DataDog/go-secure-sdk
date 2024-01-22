package fpe

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegex_CCN(t *testing.T) {
	t.Parallel()

	key, err := hex.DecodeString("D9C9D9BF96A6A53825BA8117BBD55099")
	require.NoError(t, err)
	tweak, err := hex.DecodeString("F9924954C8EBC1")
	require.NoError(t, err)

	ccnPattern := `\d{4}-\d{2}(\d{2})-(\d{4})-(\d{4})`
	ccnValue := `1111-2222-3333-4444`
	ccnAlphabet := `0123456789`

	out, err := Regex(key, tweak, ccnValue, ccnPattern, ccnAlphabet, Encrypt)
	require.NoError(t, err)
	require.Equal(t, "1111-2236-1220-1483", out)

	in, err := Regex(key, tweak, out, ccnPattern, ccnAlphabet, Decrypt)
	require.NoError(t, err)
	require.Equal(t, "1111-2222-3333-4444", in)
}

func TestRegex_SSN(t *testing.T) {
	t.Parallel()

	key, err := hex.DecodeString("D9C9D9BF96A6A53825BA8117BBD55099")
	require.NoError(t, err)
	tweak, err := hex.DecodeString("F9924954C8EBC1")
	require.NoError(t, err)

	ssnPattern := `(\d{4})-(\d{2})-(\d{4})`
	ssnValue := `1111-22-3333`
	ssnAlphabet := `0123456789`

	out, err := Regex(key, tweak, ssnValue, ssnPattern, ssnAlphabet, Encrypt)
	require.NoError(t, err)
	require.Equal(t, "5937-36-1220", out)

	in, err := Regex(key, tweak, out, ssnPattern, ssnAlphabet, Decrypt)
	require.NoError(t, err)
	require.Equal(t, "1111-22-3333", in)
}
