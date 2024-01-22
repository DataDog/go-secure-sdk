package httpsig

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"gopkg.in/square/go-jose.v2"
)

func ExampleNewRequestSigner() {
	// Decode the key as a JWK
	var pk jose.JSONWebKey
	if err := json.Unmarshal(clientPrivateJWK, &pk); err != nil {
		panic(err)
	}

	// Create a signer instance
	signer, err := NewRequestSigner(&pk)
	if err != nil {
		panic(err)
	}

	// Prepare a JSON payload
	body := []byte("{}")

	// Prepare the request
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://webhooks.datadoghq.com/v1/events", bytes.NewReader(body))
	if err != nil {
		panic(err)
	}

	// Add your API key for front authentication.
	// The signature will go through the front proxy.
	req.Header.Add("Authorization", "Bearer MY_API_KEY")

	// Sign the request will provide addition provenance authentication and
	// request integrity protection where the API Key alone can't.
	signedReq, err := signer.Sign(req, bytes.NewReader(body))
	if err != nil {
		panic(err)
	}

	// Use the signed request via your http client
	_ = signedReq
}
