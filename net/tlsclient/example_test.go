// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package tlsclient

import (
	"crypto/tls"
	"encoding/base64"

	"github.com/DataDog/go-secure-sdk/net/httpclient"
)

func ExamplePinnedDialer() {
	// Get fingerprint from configuration
	fgr, err := base64.RawStdEncoding.DecodeString("x6kjj1PTjjAA1BYMa6IzsUjPS7wE+lJ5GFPrfSFc7es")
	if err != nil {
		panic(err)
	}

	// Prepare an HTTP client.
	client := httpclient.Safe(
		httpclient.WithTLSDialer(PinnedDialer(
			&tls.Config{InsecureSkipVerify: true},
			fgr,
		)),
	)

	// Connect to remote server.
	_, err = client.Get("https://www.datadoghq.com")
	if err != nil {
		panic(err)
	}
}
