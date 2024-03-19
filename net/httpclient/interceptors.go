// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// -----------------------------------------------------------------------------

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// -----------------------------------------------------------------------------

// NewRequestFilter set up a request interceptor to authorize the request before
// being sent by the client.
func NewRequestFilter(az Authorizer, next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	if az == nil {
		az = DefaultAuthorizer
	}

	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		// Ensure allowed request
		if !az.IsRequestAuthorized(r) {
			return blockedQueryResponse(), nil
		}

		// Delegate to upstream roundtripper
		res, err := next.RoundTrip(r)
		if err != nil {
			return nil, fmt.Errorf("request filter round trip failed: %w", err)
		}
		return res, nil
	})
}

// -----------------------------------------------------------------------------

// NewResponseFilter set up a response interceptor to authorize a response from
// a client.
func NewResponseFilter(az Authorizer, next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	if az == nil {
		az = DefaultAuthorizer
	}

	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		// Delegate to upstream roundtripper
		resp, err := next.RoundTrip(r)
		if err != nil {
			return nil, fmt.Errorf("response filter round trip failed: %w", err)
		}

		// Ensure allowed response
		if !az.IsResponseAuthorized(resp) {
			return blockedQueryResponse(), nil
		}

		return resp, nil
	})
}

// -----------------------------------------------------------------------------

func blockedQueryResponse() *http.Response {
	return &http.Response{
		Body:       io.NopCloser(bytes.NewBufferString("Forbidden by client policy")),
		StatusCode: 403,
	}
}
