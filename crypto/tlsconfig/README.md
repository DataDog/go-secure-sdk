# tlsconfig

Package tlsconfig provides default TLS configuration settings.

## Types

### type [ClientCertificateProvider](options.go#L25)

`type ClientCertificateProvider func(*tls.CertificateRequestInfo) (*tls.Certificate, error)`

ClientCertificateProvider defines a function to retrieve a client certificate
instance from an external provider (Vault PKI, Envoy SDS, etc.)

### type [ClientOption](options.go#L17)

`type ClientOption func(*tls.Config) error`

ClientOption defines client specific configuration option.

### type [Config](config.go#L10)

`type Config struct { ... }`

Config represents a half configured TLS configuration. It can be made usable
by calling either of its two methods.

#### func [Build](config.go#L15)

`func Build(opts ...Option) Config`

Build creates a half configured TLS configuration.

#### func (Config) [Client](config.go#L46)

`func (c Config) Client(opts ...ClientOption) (*tls.Config, error)`

Client can be used to build a TLS configuration suitable for clients.

#### func (Config) [Server](config.go#L22)

`func (c Config) Server(opts ...ServerOption) (*tls.Config, error)`

Server can be used to build a TLS configuration suitable for servers.

### type [Option](options.go#L11)

`type Option func(*tls.Config) error`

Option defines generic TLS configuration option.

#### func [WithExternalFIPSServiceDefaults](options.go#L58)

`func WithExternalFIPSServiceDefaults() Option`

WithExternalFIPSServiceDefaults modifies a *tls.Config that is suitable for
use in communication between clients and FIPS-compliant servers where we do
not control one end of the connection.

The standards here are taken from the Mozilla SSL configuration generator
set to "Intermediate" on Dec 20, 2022 restricted to strict FIPS compliant
ciphersuites and curve preferences for ECDHE.

#### func [WithExternalServiceDefaults](options.go#L35)

`func WithExternalServiceDefaults() Option`

WithExternalServiceDefaults modifies a *tls.Config that is suitable for use
in communication between clients and servers where we do not control one end
of the connection.

The standards here are taken from the Mozilla SSL configuration generator
set to "Intermediate" on Dec 20, 2022.

#### func [WithInternalServiceDefaults](options.go#L86)

`func WithInternalServiceDefaults() Option`

WithInternalServiceDefaults modifies a *tls.Config that is suitable for use
in communication links between internal services. It is not guaranteed to be
suitable for communication to other external services as it contains a
strict definition of acceptable standards.

### type [ServerCertificateProvider](options.go#L21)

`type ServerCertificateProvider func(*tls.ClientHelloInfo) (*tls.Certificate, error)`

ServerCertificateProvider defines a function to retrieve a server certificate
instance from an external provider (Vault PKI Engine, Envoy SDS, etc.)

### type [ServerOption](options.go#L14)

`type ServerOption func(*tls.Config) error`

ServerOption defines server specific configuration option.

