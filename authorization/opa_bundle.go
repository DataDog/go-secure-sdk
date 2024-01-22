package authorization

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/rego"
)

// OpaBundle returns an Authorizer that uses an OPA bundle to authorize actions on resources.
func OpaBundle(ctx context.Context, rootFs fs.FS) (Authorizer, error) {
	// Check the arguments
	switch {
	case ctx == nil:
		return nil, errors.New("context is required")
	case rootFs == nil:
		return nil, errors.New("rootFs is required")
	}

	// Load embedded policy bundle
	dirLoader, err := bundle.NewFSLoader(rootFs)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize bundle loader: %w", err)
	}

	// Load the bundle
	b, err := bundle.NewCustomReader(dirLoader.WithFilter(func(abspath string, info fs.FileInfo, depth int) bool {
		// Check arguments
		if info == nil {
			// Skip invalid files
			return true
		}

		// Exclude test files
		return strings.HasSuffix(info.Name(), "_test.rego")
	})).Read()
	if err != nil {
		return nil, fmt.Errorf("unable to load bundle: %w", err)
	}

	// Initialize the rego compiler
	compilerOpts := []func(*rego.Rego){
		rego.Query("data.authz.result"),
		rego.ParsedBundle("datadog.security.authz.policies", &b),
	}

	// Prepare the query
	query, err := rego.New(compilerOpts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare the query: %w", err)
	}

	return &opaBundle{
		query: query,
	}, nil
}

type opaBundle struct {
	query rego.PreparedEvalQuery
}

func (a opaBundle) Can(ctx context.Context, req *Request) (*Response, error) {
	// Check the arguments
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if req == nil {
		return nil, errors.New("request is required")
	}

	// Prepare the inputs
	inputs := map[string]interface{}{
		"resource": req.Resource,
		"context":  req.Context,
	}

	// Add the action
	if req.Action != "" {
		inputs["action"] = req.Action
	}
	if req.User != nil {
		inputs["user"] = req.User
	}

	// Evaluate the request
	results, err := a.query.Eval(ctx,
		rego.EvalInput(inputs),
	)

	// Check the result as the pollicy is user provided we have to be defensive
	// to prevent authorization bypasses.
	switch {
	case err != nil:
		return nil, fmt.Errorf("failed to evaluate query: %w", err)
	case len(results) == 0:
		return nil, errors.New("policy decision without results returned")
	case len(results) > 1:
		return nil, errors.New("policy decision with multiple results returned")
	case len(results[0].Expressions) == 0:
		return nil, errors.New("policy decision without expressions returned")
	case len(results[0].Expressions) > 1:
		return nil, errors.New("policy decision with multiple expressions returned")
	case results[0].Expressions[0] == nil:
		return nil, errors.New("policy decision with nil first expression returned")
	default:
		// Good to go
	}

	// Validate result value
	result := results[0].Expressions[0].Value
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("policy decision result must be a map, got %T", result)
	}

	// Check mandatory result keys
	if _, ok := resultMap["allow"]; !ok {
		return nil, errors.New("policy decision result must contain 'allow' key")
	}

	// Check the result
	var res Response
	if err := mapstructure.Decode(resultMap, &res); err != nil {
		return nil, fmt.Errorf("failed to decode result: %w", err)
	}

	return &res, nil
}
