package password

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultHasher(t *testing.T) {
	t.Parallel()

	password := []byte("foo")

	encoded, err := Hash(password)
	require.NoError(t, err, "Password encoding should not raise error")
	require.NotNil(t, encoded, "Encoded password should not be nil")

	valid, err := Verify(encoded, password)
	require.NoError(t, err, "Password verification should not raise error")
	require.True(t, valid, "Password should be valid")

	upgrade := NeedsEncodingUpgrade(encoded)
	require.False(t, upgrade, "Password should not need upgrades")
}
