package authorization

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/authorization/testdata"
)

func TestOpaBundle(t *testing.T) {
	t.Parallel()

	t.Run("nil context", func(t *testing.T) {
		t.Parallel()

		// Create the authorizer
		//nolint:SA1012
		underTest, err := OpaBundle(nil, nil)
		require.Error(t, err)
		require.Nil(t, underTest)
	})

	t.Run("nil rootfs", func(t *testing.T) {
		t.Parallel()

		// Create the authorizer
		underTest, err := OpaBundle(context.Background(), nil)
		require.Error(t, err)
		require.Nil(t, underTest)
	})

	t.Run("empty policy", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		rootfs := fstest.MapFS{
			"policy.rego": &fstest.MapFile{
				Data: []byte(``),
			},
		}

		// Create the authorizer
		underTest, err := OpaBundle(ctx, rootfs)
		require.Error(t, err)
		require.Nil(t, underTest)
	})

	t.Run("invalid policy", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		rootfs := fstest.MapFS{
			"policy.rego": &fstest.MapFile{
				Data: []byte(`$$`),
			},
		}

		// Create the authorizer
		underTest, err := OpaBundle(ctx, rootfs)
		require.Error(t, err)
		require.Nil(t, underTest)
	})

	t.Run("policy compilation error", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		rootfs := fstest.MapFS{
			"policy.rego": &fstest.MapFile{
				Data: []byte(`
					package authz
					
					allow { error }
				`),
			},
		}

		// Create the authorizer
		underTest, err := OpaBundle(ctx, rootfs)
		require.Error(t, err)
		require.Nil(t, underTest)
	})

	t.Run("valid policy", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		rootfs := fstest.MapFS{
			"policy.rego": &fstest.MapFile{
				Data: []byte(`
					package authz
					
					allow { true }
				`),
			},
		}

		// Create the authorizer
		underTest, err := OpaBundle(ctx, rootfs)
		require.NoError(t, err)
		require.NotNil(t, underTest)
	})

	t.Run("valid policy with data", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		rootfs := fstest.MapFS{
			"authz/authz.rego": &fstest.MapFile{
				Data: []byte(`
					package authz
					
					import future.keywords.if
					
					import data.decision
					
					default result = {"allow": false, "reason": "unauthorized resource access"}
					
					result = {"allow": true} if { decision.override == true }
			`),
			},
			"decision/data.json": &fstest.MapFile{
				Data: []byte(`{"override": true}`),
			},
		}

		// Create the authorizer
		underTest, err := OpaBundle(ctx, rootfs)
		require.NoError(t, err)
		require.NotNil(t, underTest)

		// Create the request
		req := &Request{}

		// Authorize the request
		resp, err := underTest.Can(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.Allow)
	})
}

func TestOpaBundleCan(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	rootfs := fstest.MapFS{
		"policy.rego": &fstest.MapFile{
			Data: []byte(`
				package authz
				
				import future.keywords.in

				default result = {"allow": false,"reason": "unauthorized resource access"}
				
				result = { "allow": true } if { 
					some g in input.user.groups
					g == "group:123" 
				}
			`),
		},
	}

	// Create the authorizer
	underTest, err := OpaBundle(ctx, rootfs)
	require.NoError(t, err)
	require.NotNil(t, underTest)

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

func TestOpaBundleCanNilRequest(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	rootfs := fstest.MapFS{
		"policy.rego": &fstest.MapFile{
			Data: []byte("package authz\n\nallow { true }"),
		},
	}

	// Create the authorizer
	underTest, err := OpaBundle(ctx, rootfs)
	require.NoError(t, err)
	require.NotNil(t, underTest)

	// Authorize the request
	resp, err := underTest.Can(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestOpaBundleCanNoDecision(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	rootfs := fstest.MapFS{
		"policy.rego": &fstest.MapFile{
			Data: []byte("package authz\n\n"),
		},
	}

	// Create the authorizer
	underTest, err := OpaBundle(ctx, rootfs)
	require.NoError(t, err)
	require.NotNil(t, underTest)

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
	require.Error(t, err)
	require.Nil(t, resp)
	require.Equal(t, "policy decision without results returned", err.Error())
}

func TestOpaBundleCanIncompatibleResult(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	rootfs := fstest.MapFS{
		"policy.rego": &fstest.MapFile{
			Data: []byte("package authz\n\nresult := []"),
		},
	}

	// Create the authorizer
	underTest, err := OpaBundle(ctx, rootfs)
	require.NoError(t, err)
	require.NotNil(t, underTest)

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
	require.Error(t, err)
	require.Nil(t, resp)
	require.Equal(t, "policy decision result must be a map, got []interface {}", err.Error())
}

func TestOpaBundleExternal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Create the authorizer
	underTest, err := OpaBundle(ctx, testdata.Policies)
	require.NoError(t, err)
	require.NotNil(t, underTest)

	t.Run("authorized request", func(t *testing.T) {
		t.Parallel()

		// Create the request
		req := &Request{
			User: KV{
				"subject": "user:123",
				"groups":  []string{"administrators"},
			},
		}

		// Authorize the request
		resp, err := underTest.Can(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.Allow)
	})

	t.Run("unauthorized request", func(t *testing.T) {
		t.Parallel()

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
		require.False(t, resp.Allow)
		require.Equal(t, "Not authorized", resp.Reason)
	})

	t.Run("unauthorized request on code freeze", func(t *testing.T) {
		t.Parallel()

		// Create the request
		req := &Request{
			User: KV{
				"subject": "user:123",
				"groups":  []string{"administrators"},
			},
			Context: map[string]interface{}{
				"code_freeze": true,
			},
		}

		// Authorize the request
		resp, err := underTest.Can(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.Allow)
		require.Equal(t, "Access disabled during code freeze", resp.Reason)
	})
}
