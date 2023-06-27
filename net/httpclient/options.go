// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
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

// WithDisableKeepAlives disables the request filtering feature.
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
