package hasher

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

func Benchmark_Strategies(b *testing.B) {
	salt, err := randomness.Bytes(32)
	require.NoError(b, err)

	pwd := []byte("Hello World!")

	for alg, versions := range Strategies {
		for v, sb := range versions {
			b.Run(fmt.Sprintf("Algorithm %x / version %x", alg, v), func(b *testing.B) {
				d := sb(func() []byte { return salt })
				for i := 0; i < b.N; i++ {
					_, err := d.Hash(pwd)
					require.NoError(b, err)
				}
			})
		}
	}
}
