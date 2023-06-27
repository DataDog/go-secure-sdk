// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package tlsconfig

import (
	"crypto/tls"
)

// Option defines generic TLS configuration option.
type Option func(*tls.Config) error

// ServerOption defines server specific configuration option.
type ServerOption func(*tls.Config) error

// ClientOption defines client specific configuration option.
type ClientOption func(*tls.Config) error

// ServerCertificateProvider defines a function to retrieve a server certificate
// instance from an external provider (Vault PKI Engine, Envoy SDS, etc.)
type ServerCertificateProvider func(*tls.ClientHelloInfo) (*tls.Certificate, error)

// ClientCertificateProvider defines a function to retrieve a client certificate
// instance from an external provider (Vault PKI, Envoy SDS, etc.)
type ClientCertificateProvider func(*tls.CertificateRequestInfo) (*tls.Certificate, error)

// -----------------------------------------------------------------------------

// WithExternalServiceDefaults modifies a *tls.Config that is suitable for use
// in communication between clients and servers where we do not control one end
// of the connection.
//
// The standards here are taken from the Mozilla SSL configuration generator
// set to "Intermediate" on Dec 20, 2022.
func WithExternalServiceDefaults() Option {
	return func(c *tls.Config) error {
		c.MinVersion = tls.VersionTLS12
		c.MaxVersion = tls.VersionTLS13
		c.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		}
		return nil
	}
}

// WithExternalFIPSServiceDefaults modifies a *tls.Config that is suitable for
// use in communication between clients and FIPS-compliant servers where we do
// not control one end of the connection.
//
// The standards here are taken from the Mozilla SSL configuration generator
// set to "Intermediate" on Dec 20, 2022 restricted to strict FIPS compliant
// ciphersuites and curve preferences for ECDHE.
func WithExternalFIPSServiceDefaults() Option {
	return func(c *tls.Config) error {
		c.MinVersion = tls.VersionTLS12
		// NIST SP 800-52 encourages TLS v1.3 migration
		c.MaxVersion = tls.VersionTLS13
		c.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			// For compatibility
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		}
		c.CurvePreferences = []tls.CurveID{
			// X25519 removed because it's not FIPS compliant
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		}
		return nil
	}
}

// WithInternalServiceDefaults modifies a *tls.Config that is suitable for use
// in communication links between internal services. It is not guaranteed to be
// suitable for communication to other external services as it contains a
// strict definition of acceptable standards.
func WithInternalServiceDefaults() Option {
	return func(c *tls.Config) error {
		// TLSv1.3 is enforced for internal service to service communication.
		c.MinVersion = tls.VersionTLS13
		c.MaxVersion = tls.VersionTLS13
		return nil
	}
}
