package privatejwt

import (
	"context"
	"time"

	"gopkg.in/square/go-jose.v2"
)

const (
	jtiLength          = 8
	minExpiration      = 10 * time.Second
	maxExpiration      = 10 * time.Minute
	clockSkewTolerance = 10 * time.Second
)

// ClientKeysResolver respresents client identity lookup contract.
type ClientKeysResolver func(ctx context.Context, id string) ([]*jose.JSONWebKey, error)

// Signer describes attestation signer contract.
type Signer interface {
	// Sign an attestion verifiable by the target audience.
	Sign(ctx context.Context, audience string) (string, error)
}

// Verifier describes assertion verifier contract.
type Verifier interface {
	// Verify the given assertion.
	Verify(ctx context.Context, clientID, assertion string) (*Claims, error)
}
