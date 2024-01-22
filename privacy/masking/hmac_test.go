package masking

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHMAC(t *testing.T) {
	t.Parallel()

	t.Run("key too short", func(t *testing.T) {
		t.Parallel()

		out, err := HMAC("employeeID", []byte{})
		require.Error(t, err)
		require.Empty(t, out)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		key := []byte(`]P_Vk0tsK%:7Sq_;iOL.Oc:RQ>OO9B'zkhd<yba_e0V\&*5T1c|B%UH,BBi&Hu.`)

		out, err := HMAC("employeeID", key)
		require.NoError(t, err)
		require.Equal(t, "fSatTzi7qmE5MIQ3C2Jz63KW0JCyzrhYzLo9k0_D8OQ", out)
	})

	t.Run("different keys", func(t *testing.T) {
		t.Parallel()

		key := []byte(`]P_Vk0tsK%:7Sq_;iOL.Oc:RQ>OO9B'zkhd<yba_e0V\&*5T1c|B%UH,BBi&Hu.`)
		out, err := HMAC("employeeID", key)
		require.NoError(t, err)

		key2 := []byte(`=L|,GE/N6QAze=c&qQ]MYP?Z)0[Q#(af%+:nuh3[N4.APZvfo9,XJ;=Khn~{/fI`)
		out2, err := HMAC("employeeID", key2)
		require.NoError(t, err)

		require.NotEqual(t, out, out2)
		require.NotEqual(t, "employeeID", out)
	})
}

func TestNonDeterministicHMAC(t *testing.T) {
	t.Parallel()

	t.Run("key too short", func(t *testing.T) {
		t.Parallel()

		out, err := NonDeterministicHMAC("employeeID", []byte{})
		require.Error(t, err)
		require.Empty(t, out)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		key := []byte(`]P_Vk0tsK%:7Sq_;iOL.Oc:RQ>OO9B'zkhd<yba_e0V\&*5T1c|B%UH,BBi&Hu.`)

		out, err := NonDeterministicHMAC("employeeID", key)
		require.NoError(t, err)
		require.NotEmpty(t, out)

		out2, err := NonDeterministicHMAC("employeeID", key)
		require.NoError(t, err)
		require.NotEmpty(t, out2)

		require.NotEqual(t, out, out2)
	})
}

//nolint:errcheck
func BenchmarkHMAC(b *testing.B) {
	key := []byte(`]P_Vk0tsK%:7Sq_;iOL.Oc:RQ>OO9B'zkhd<yba_e0V\&*5T1c|B%UH,BBi&Hu.`)
	msg := "employeeID"

	for i := 0; i < b.N; i++ {
		HMAC(msg, key)
	}
}

//nolint:errcheck
func BenchmarkNonDeterministicHMA(b *testing.B) {
	key := []byte(`]P_Vk0tsK%:7Sq_;iOL.Oc:RQ>OO9B'zkhd<yba_e0V\&*5T1c|B%UH,BBi&Hu.`)
	msg := "employeeID"

	for i := 0; i < b.N; i++ {
		NonDeterministicHMAC(msg, key)
	}
}
