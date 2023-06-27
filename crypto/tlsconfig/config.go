// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package tlsconfig

import "crypto/tls"

// Config represents a half configured TLS configuration. It can be made usable
// by calling either of its two methods.
type Config struct {
	opts []Option
}

// Build creates a half configured TLS configuration.
func Build(opts ...Option) Config {
	return Config{
		opts: opts,
	}
}

// Server can be used to build a TLS configuration suitable for servers.
func (c Config) Server(opts ...ServerOption) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	// Apply general configuration options
	for _, opt := range c.opts {
		if err := opt(config); err != nil {
			return nil, err
		}
	}

	// Apply call specific options
	for _, opt := range opts {
		if err := opt(config); err != nil {
			return nil, err
		}
	}

	return config, nil
}

// Client can be used to build a TLS configuration suitable for clients.
func (c Config) Client(opts ...ClientOption) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	// Apply general configuration options
	for _, opt := range c.opts {
		if err := opt(config); err != nil {
			return nil, err
		}
	}

	// Apply call specific options
	for _, opt := range opts {
		if err := opt(config); err != nil {
			return nil, err
		}
	}

	return config, nil
}
