// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package tlsclient

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/DataDog/go-secure-sdk/crypto/keyutil"
)

const (
	// Specifies the maximum allowed length of the certificate chain in TLS
	// handshaking.
	maxCertificateCount = 25
)

var (
	// ErrNoPinMatch is raised when certificate fingerprints doesn't match the
	// given fingerprint.
	ErrNoPinMatch = errors.New("no certificate match the expected fingerprint")

	// ErrCertificateChainTooLong is raised when the certificate chain returned
	// by the TLS handshake is too large.
	ErrCertificateChainTooLong = fmt.Errorf("the certificate chain exceeds the maximum allowed length (%d)", maxCertificateCount)
)

// Dialer represents network dialer function for mocking purpose.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// PinnedDialer uses the given tlsconfig configuration to establish an initial
// connection with the remote peer, and validate the certificate public key
// fingerprint against the given fingerprint.
//
// Use this dialer to ensure a remote peer certificate. This helps to mitigate
// DNS based attacks which could be used to reroute/proxy TLS traffic through
// an unauthorized peer, and drive the risk to total confidentiality compromise.
func PinnedDialer(cfg *tls.Config, fingerPrint []byte) Dialer {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Check argument
		if cfg == nil {
			return nil, errors.New("bootstrap TLS configuration must be provided")
		}

		// Clone the given configuration
		clientConfig := cfg.Clone()

		// Try to connect to the remote server first to retrieve certificates.
		c, err := tls.Dial(network, addr, clientConfig)
		if err != nil {
			return nil, fmt.Errorf("unable to establish initial TLS connection to retrieve certificates: %w", err)
		}

		connState := c.ConnectionState()
		keyPinValid := false

		// Ensure acceptable certificate count
		if len(connState.PeerCertificates) > maxCertificateCount {
			return nil, ErrCertificateChainTooLong
		}

		// Iterate over all returned certificates
		for _, peerCert := range connState.PeerCertificates {
			// Check if context has error to stop the validation prematurely.
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			// Compute public key certificate fingerprint
			hash, err := keyutil.PublicKeyFingerprint(peerCert)
			if err != nil {
				return c, fmt.Errorf("unable to compute public key fingerprint: %w", err)
			}

			// Check equality whith provided fingerprint
			if subtle.ConstantTimeCompare(hash, fingerPrint) == 1 {
				keyPinValid = true
			}

			// Continue to process all certificates
		}
		if !keyPinValid {
			return nil, ErrNoPinMatch
		}

		return c, nil
	}
}
