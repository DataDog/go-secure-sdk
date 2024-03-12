package httpclient

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// Option represents http client functional option pattern type.
type Option func(*options)

type options struct {
	timeout               time.Duration
	disableKeepAlives     bool
	disableRequestFilter  bool
	disableResponseFilter bool
	followRedirect        bool
	maxRedirectionCount   int
	tlsConfig             *tls.Config
	tlsDialContext        func(context.Context, string, string) (net.Conn, error)
}

// WithTimeout sets the client timeout.
func WithTimeout(value time.Duration) Option {
	return func(o *options) {
		o.timeout = value
	}
}

// WithDisableKeepAlives disables the keep alive feature.
func WithDisableKeepAlives(value bool) Option {
	return func(o *options) {
		o.disableKeepAlives = value
	}
}

// WithDisableRequestFilter disables the request filtering feature.
func WithDisableRequestFilter(value bool) Option {
	return func(o *options) {
		o.disableRequestFilter = value
	}
}

// WithDisableResponseFilter disables the response filtering feature.
func WithDisableResponseFilter(value bool) Option {
	return func(o *options) {
		o.disableResponseFilter = value
	}
}

// WithFollowRedirect disables the redirection follower feature.
func WithFollowRedirect(value bool) Option {
	return func(o *options) {
		o.followRedirect = value
	}
}

// WithMaxRedirectionCount sets the maximum redirection count before returning
// an error.
func WithMaxRedirectionCount(value int) Option {
	return func(o *options) {
		o.maxRedirectionCount = value
	}
}

// WithTLSClientConfig sets the HTTP client TLS configuration to use for connection.
func WithTLSClientConfig(value *tls.Config) Option {
	return func(o *options) {
		o.tlsConfig = value
	}
}

// WithTLSDialer sets the TLS Dialer function to use to establish the connection.
func WithTLSDialer(dialer func(context.Context, string, string) (net.Conn, error)) Option {
	return func(o *options) {
		o.tlsDialContext = dialer
	}
}
