// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"

	"golang.org/x/net/http2"
)

// DefaultClient represents a safe HTTP client instance.
var DefaultClient = Safe()

// UnSafe returns a HTTP client with default transport settings only.
func UnSafe(opts ...Option) *http.Client {
	return NewClient(nil, opts...)
}

// Safe returns a safe HTTP client with the default authorizer
// implementation.
func Safe(opts ...Option) *http.Client {
	return NewClient(DefaultAuthorizer, opts...)
}

// NewClient is used to create a safe http client with the given authorizer
// implementation.
func NewClient(az Authorizer, opts ...Option) *http.Client {
	// Create default settings
	dopts := &options{
		timeout:               30 * time.Second,
		disableKeepAlives:     false,
		disableRequestFilter:  false,
		disableResponseFilter: false,
		followRedirect:        false,
		maxRedirectionCount:   5,
	}
	for _, o := range opts {
		o(dopts)
	}

	// Create a safe dialer
	dialer := &net.Dialer{
		// Disable the fallback delay (Happy Eyeballs algorithm)
		FallbackDelay: -1 * time.Millisecond,
		Timeout:       dopts.timeout,
		KeepAlive:     dopts.timeout,
		Control:       safeControl(az),
		// see: net.DefaultResolver
		Resolver: &net.Resolver{
			// Prefer Go's built-in DNS resolver.
			PreferGo: true,
		},
	}

	// Prepare safe transport settings
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     dopts.disableKeepAlives,
	}
	if dopts.tlsConfig != nil {
		tr.TLSClientConfig = dopts.tlsConfig
	}
	if dopts.tlsDialContext != nil {
		tr.DialTLSContext = dopts.tlsDialContext
	}

	// Reduce interface type
	var t http.RoundTripper = tr

	// Set the HTTP2 transport settings
	http2Trans, err := http2.ConfigureTransports(tr)
	if err == nil {
		http2Trans.ReadIdleTimeout = 31 * time.Second
	}

	// Decorate the HTTP round-tripper with request / response filter.
	if az != nil {
		if !dopts.disableRequestFilter {
			t = NewRequestFilter(az, t)
		}
		if !dopts.disableResponseFilter {
			t = NewResponseFilter(az, t)
		}
	}

	// Follow redirections
	redirectStrategy := noFollowRedirect
	if dopts.followRedirect {
		redirectStrategy = maxRedirections(dopts.maxRedirectionCount, az)
	}

	// Wrap everything in a HTTP client instance.
	return &http.Client{
		Transport:     t,
		Timeout:       dopts.timeout,
		CheckRedirect: redirectStrategy,
	}
}

// -----------------------------------------------------------------------------

// safeControl returns a socket control function used to instrument the dialer.
func safeControl(az Authorizer) func(string, string, syscall.RawConn) error {
	// If no authorizer provided returning nil will restore default behavior.
	if az == nil {
		return nil
	}

	return func(network, address string, rc syscall.RawConn) error {
		// Check network / address authorization
		if allow, err := az.IsNetworkAddressAuthorized(network, address); !allow {
			return fmt.Errorf("%s/%s is not authorized by the client: %w", network, address, err)
		}

		return nil
	}
}

// checkRedirectFunc is the function prototype used to describes the follow redirect strategy.
type checkRedirectFunc func(req *http.Request, via []*http.Request) error

// noFollowRedirect disables the redirection follower feature.
func noFollowRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

// maxRedirections enforces a maximum redirection count.
func maxRedirections(count int, az Authorizer) checkRedirectFunc {
	if az == nil {
		az = DefaultAuthorizer
	}

	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= count {
			return fmt.Errorf("stopped after %d redirects", count)
		}
		for _, r := range via {
			if !az.IsRequestAuthorized(r) {
				return errors.New("a redirected request has been blocked by the client policy")
			}
		}

		return nil
	}
}
