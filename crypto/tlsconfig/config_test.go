package tlsconfig

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExternalServiceDefaults(t *testing.T) {
	t.Parallel()

	clientConfig, err := Build(WithExternalServiceDefaults()).Client()
	require.NoError(t, err)
	require.NotNil(t, clientConfig)

	serverConfig, err := Build(WithExternalServiceDefaults()).Server()
	require.NoError(t, err)
	require.NotNil(t, serverConfig)

	tcs := []struct {
		name   string
		config *tls.Config
	}{
		{
			name:   "client",
			config: clientConfig,
		},
		{
			name:   "server",
			config: serverConfig,
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			config := tc.config

			require.Equal(t, uint16(tls.VersionTLS12), config.MinVersion)
			require.Equal(t, uint16(tls.VersionTLS13), config.MaxVersion)
			require.Equal(t, []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			}, config.CipherSuites)
		})
	}
}

func TestExternalFIPSServiceDefaults(t *testing.T) {
	t.Parallel()

	clientConfig, err := Build(WithExternalFIPSServiceDefaults()).Client()
	require.NoError(t, err)
	require.NotNil(t, clientConfig)

	serverConfig, err := Build(WithExternalFIPSServiceDefaults()).Server()
	require.NoError(t, err)
	require.NotNil(t, serverConfig)

	tcs := []struct {
		name   string
		config *tls.Config
	}{
		{
			name:   "client",
			config: clientConfig,
		},
		{
			name:   "server",
			config: serverConfig,
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			config := tc.config

			require.Equal(t, uint16(tls.VersionTLS12), config.MinVersion)
			require.Equal(t, uint16(tls.VersionTLS13), config.MaxVersion)
			require.Equal(t, []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				// For compatibility
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			}, config.CipherSuites)
			require.Equal(t, []tls.CurveID{
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
			}, config.CurvePreferences)
		})
	}
}

func TestInternalSServiceDefaults(t *testing.T) {
	t.Parallel()

	clientConfig, err := Build(WithInternalServiceDefaults()).Client()
	require.NoError(t, err)
	require.NotNil(t, clientConfig)

	serverConfig, err := Build(WithInternalServiceDefaults()).Server()
	require.NoError(t, err)
	require.NotNil(t, serverConfig)

	tcs := []struct {
		name   string
		config *tls.Config
	}{
		{
			name:   "client",
			config: clientConfig,
		},
		{
			name:   "server",
			config: serverConfig,
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			config := tc.config

			require.Equal(t, uint16(tls.VersionTLS13), config.MinVersion)
			require.Equal(t, uint16(tls.VersionTLS13), config.MaxVersion)
			require.Empty(t, config.CipherSuites)
			require.Empty(t, config.CurvePreferences)
		})
	}
}
