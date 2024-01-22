package authorization

import (
	"context"
)

// Authorizer is the interface that wraps the basic Can method.
type Authorizer interface {
	Can(ctx context.Context, req *Request) (*Response, error)
}

// KV is a map of string to any.
type KV map[string]any

// Request is the structure that wraps the information needed to authorize an
// action on a resource.
type Request struct {
	// Action is the action to authorize.
	// It is recommended to use namespaced verbs to describe a permission, like
	// "email:send" or "user:read".
	//
	// The action can be used to define the granularity of the authorization.
	// Consider answering the question "What for?" when defining an action.
	Action string `json:"action" mapstructure:"action"`

	// User is the user identity that is requesting the action.
	// The user property must qualify a biological person.
	// Generally authenticated by token based authentication.
	//
	// Consider answering the question "Who?" when defining a user.
	User KV `json:"user" mapstructure:"user"`

	// Client is the client identity that is requesting the action.
	// The client property can be a service account, an application, a device, etc.
	// Generally authenticated by transport/network based authentication.
	//
	// Consider answering the question "Whom?" when defining a client.
	Client KV `json:"client" mapstructure:"client"`

	// Resource contains the resource details that is being requested.
	//
	// Consider answering the question "What?" when defining a resource.
	Resource KV `json:"resource" mapstructure:"resource"`

	// Context is the context of the request.
	// It can be used to pass additional information to the authorizer.
	//
	// Consider answering the question "From where?" when defining a context.
	Context KV `json:"context" mapstructure:"context"`
}

// Response is the structure that wraps the result of an authorization request.
type Response struct {
	// Allow is the result of the authorization request.
	Allow bool `json:"allow" mapstructure:"allow"`
	// Reason is the reason for the authorization result.
	// The reason can be filled to justify an authorization decision.
	Reason string `json:"reason" mapstructure:"reason"`
	// Rules is the list of rules that were evaluated during the authorization.
	// It can be used to debug the authorization decision.
	Rules map[string]Decision `json:"rules" mapstructure:"rules"`
}

// Decision is the structure that wraps the information about a rule that was
// evaluated during an authorization request.
type Decision struct {
	// Allow is the result of the rule evaluation.
	Allow bool `json:"allow" mapstructure:"allow"`
	// Reason is the reason for the rule evaluation result.
	Reason string `json:"reason" mapstructure:"reason"`
}
