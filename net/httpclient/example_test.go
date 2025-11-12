// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"
)

func ExampleSafe() {
	c := Safe()

	// Query AWS Metatadata
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	if err != nil {
		panic(err)
	}

	resp, err := c.Do(r)
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	// Output: Get "http://169.254.169.254/latest/meta-data/": response filter round trip failed: request filter round trip failed: dial tcp 169.254.169.254:80: tcp4/169.254.169.254:80 is not authorized by the client: "169.254.169.254" address is link local unicast
	fmt.Println(err.Error())
}

func ExampleUnSafe() {
	// Create a fake http server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "", http.StatusFound)
	}))

	c := UnSafe(
		// Reduce timeout
		WithTimeout(3*time.Second),
		// Disable keep alives
		WithDisableKeepAlives(true),
		// Default for unsafe
		WithDisableRequestFilter(true),
		// Default for unsafe
		WithDisableResponseFilter(true),
		// Enable follow redirect
		WithFollowRedirect(true),
		// Change max redirection count
		WithMaxRedirectionCount(2),
	)

	// Query AWS Metatadata
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, mockServer.URL, nil)
	if err != nil {
		panic(err)
	}

	resp, err := c.Do(r)
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	// Output: Get "/": stopped after 2 redirects
	fmt.Println(err.Error())
}
