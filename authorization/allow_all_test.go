package authorization

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllowAll(t *testing.T) {
	t.Parallel()

	// Create the authorizer
	underTest := AllowAll()

	// Create the request
	req := &Request{
		Action: "embassy:delete",
		User: KV{
			"subject": "user:123",
			"groups":  []string{"group:123"},
		},
	}

	// Authorize the request
	resp, err := underTest.Can(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.Allow)
}
