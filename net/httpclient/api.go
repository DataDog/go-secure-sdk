// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package httpclient

import "net/http"

//go:generate mockgen -destination mock/authorizer.gen.go -package mock github.com/DataDog/go-secure-sdk/net/httpclient Authorizer

// Authorizer describes socket level authorization gates.
type Authorizer interface {
	// IsNetworkAddressAuthorized returns true if the given network/address
	// tuple is allowed.
	IsNetworkAddressAuthorized(network, address string) (bool, error)
	// IsRequestAuthorized returns true if the request is allowed.
	IsRequestAuthorized(req *http.Request) bool
	// IsResponseAuthorized returns true if the response is allowed.
	IsResponseAuthorized(res *http.Response) bool
}
