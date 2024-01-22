package authorization

import "context"

// AllowAll returns an Authorizer that allows all actions on all resources.
func AllowAll() Authorizer {
	return allowAll{}
}

type allowAll struct{}

func (a allowAll) Can(_ context.Context, _ *Request) (*Response, error) {
	return &Response{
		Allow: true,
	}, nil
}
