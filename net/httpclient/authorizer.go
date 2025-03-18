// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
)

var _ Authorizer = (*ssrfAuthorizer)(nil)
var _ Authorizer = (*internalOnlyAuthorizer)(nil)

type ssrfAuthorizer struct{}
type internalOnlyAuthorizer struct{}

// DefaultAuthorizer exposes the default authorizer instance.
var DefaultAuthorizer = &ssrfAuthorizer{}

// InternalOnlyAuthorizer exposes an authorizer instance that only allows internal addresses.
var InternalOnlyAuthorizer = &internalOnlyAuthorizer{}

// IsNetworkAddressAuthorized returns true if the given network/host/port
// tuple is allowed.
func (az *ssrfAuthorizer) IsNetworkAddressAuthorized(network, address string) (bool, error) {
	// Enforce valid network
	switch network {
	case "tcp", "tcp4", "tcp6":
		// Acceptable
	default:
		return false, fmt.Errorf("the network %q usage is forbidden by the client policy", network)
	}

	// Enforce not blank address
	if address == "" {
		return false, errors.New("the address can't be blank")
	}

	// Split host/port if any (TCP connection assumed here.)
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false, fmt.Errorf("unable to split host and port from address %q: %w", address, err)
	}

	// Parse IP address from address (This is always an IP address, this
	// handler is called after a DNS resolution.)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false, fmt.Errorf("unable to parse given address %q as an IP: %w", address, err)
	}

	switch {
	case ip.IsLoopback():
		return false, fmt.Errorf("%q address is loopback", host)
	case ip.IsLinkLocalUnicast():
		return false, fmt.Errorf("%q address is link local unicast", host)
	case ip.IsPrivate():
		return false, fmt.Errorf("%q address is private", host)
	default:
	}

	return true, nil
}

// IsNetworkAddressAuthorized returns true if the given network/host/port
// tuple is allowed.
func (az *internalOnlyAuthorizer) IsNetworkAddressAuthorized(network, address string) (bool, error) {
	// Enforce valid network
	switch network {
	case "tcp", "tcp4", "tcp6":
		// Acceptable
	default:
		return false, fmt.Errorf("the network %q usage is forbidden by the client policy", network)
	}

	// Enforce not blank address
	if address == "" {
		return false, errors.New("the address can't be blank")
	}

	// Split host/port if any (TCP connection assumed here.)
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false, fmt.Errorf("unable to split host and port from address %q: %w", address, err)
	}

	// Parse IP address from address (This is always an IP address, this
	// handler is called after a DNS resolution.)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false, fmt.Errorf("unable to parse given address %q as an IP: %w", address, err)
	}

	// Only allow internal addresses
	switch {
	case ip.IsLoopback():
		return true, nil
	case ip.IsLinkLocalUnicast():
		return true, nil
	case ip.IsPrivate():
		return true, nil
	default:
		return false, fmt.Errorf("%q address is not internal", host)
	}
}

// IsRequestAuthorized returns true if the request is allowed.
func (az *ssrfAuthorizer) IsRequestAuthorized(req *http.Request) bool {
	// No filtering implemented yet.
	return true
}

// IsResponseAuthorized returns true if the response is allowed.
func (az *ssrfAuthorizer) IsResponseAuthorized(res *http.Response) bool {
	// No filtering implemented yet.
	return true
}

// IsRequestAuthorized returns true if the request is allowed.
func (az *internalOnlyAuthorizer) IsRequestAuthorized(req *http.Request) bool {
	// No filtering implemented yet.
	return true
}

// IsResponseAuthorized returns true if the response is allowed.
func (az *internalOnlyAuthorizer) IsResponseAuthorized(res *http.Response) bool {
	// No filtering implemented yet.
	return true
}
