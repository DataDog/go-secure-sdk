package logical

import (
	"context"

	"github.com/hashicorp/vault/api"
)

//go:generate mockgen -destination logical.mock.go -package logical github.com/DataDog/go-secure-sdk/kms/vault/logical Logical

// Logical backend interface
type Logical interface {
	ReadWithContext(ctx context.Context, path string) (*api.Secret, error)
	ReadWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*api.Secret, error)
	WriteWithContext(ctx context.Context, path string, data map[string]interface{}) (*api.Secret, error)
}
