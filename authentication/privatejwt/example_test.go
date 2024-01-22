package privatejwt

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"gopkg.in/square/go-jose.v2"
)

var clientPrivateJWK = []byte(`{
    "kty": "EC",
    "d": "74RBzgBeUoWhm3UgrNtyyM-nPfnc-Gqnf6PJHXFOYhw",
    "use": "sig",
    "crv": "P-256",
    "x": "ZThHZviy98QoHBmiFuh6qeRFlU9qZJQcHLECNTiyaj8",
    "y": "_PC72xTaT4mMRsdK8YVK00owFH1SsT25tbmRBhxlIGM",
    "alg": "ES256"
}`)

func ExampleAssertionSigner() {
	// Decode the key as a JWK
	var pk jose.JSONWebKey
	if err := json.Unmarshal(clientPrivateJWK, &pk); err != nil {
		panic(err)
	}

	// Create a client assertion signer.
	signer, err := AssertionSigner("runner-client", &pk, "123456789", 5*time.Minute)
	if err != nil {
		panic(err)
	}

	// Create client assertion targeting the given endpoint
	assertion, err := signer.Sign(context.Background(), "https://runner-gw.us1.datadog.com")
	if err != nil {
		panic(err)
	}

	// Sample Output: eyJhbGciOiJFUzI1NiIsInR5cCI6ImNsaWVudF9hc3NlcnRpb24rSldUIn0.eyJhdWQiOiJodHRwczovL3J1bm5lci1ndy51czEuZGF0YWRvZy5jb20iLCJleHAiOiIyMDIzLTAyLTIwVDA4OjQ4OjI2LjA0OTA3N1oiLCJpYXQiOiIyMDIzLTAyLTIwVDA4OjQzOjI2LjA0OTA3N1oiLCJpc3MiOiIxMjM0NTY3ODkiLCJqdGkiOiJ1Z0dpazdCbCIsInN1YiI6IjEyMzQ1Njc4OSJ9.wBvOVTLDZeY5UF7Gy5YVxaJvbspLteNZmhHvhIhZTsp5hmNtdKHEljaZyTQuDd0giEsu997ZsG_RLRK4zMI6HQ
	fmt.Println(assertion)
}

func ExampleAssertionVerifier() {
	// Decode the key as a JWK
	var pk jose.JSONWebKey
	if err := json.Unmarshal(clientPrivateJWK, &pk); err != nil {
		panic(err)
	}

	clientID := "123456789"
	audience := "https://runner-gw.us1.datadog.com"

	// Create a client assertion signer.
	signer, err := AssertionSigner("runner-client", &pk, "123456789", 5*time.Minute)
	if err != nil {
		panic(err)
	}

	// Create client assertion targeting the given endpoint
	assertion, err := signer.Sign(context.Background(), audience)
	if err != nil {
		panic(err)
	}

	// Send the ClientID and the assertion to the verifier.

	// Create an assertion verifier.
	verifier, err := AssertionVerifier("runner-client", func(ctx context.Context, id string) ([]*jose.JSONWebKey, error) {
		// Ensure ClientID format before running any repository-related queries.
		// Use id to lookup the client keys in your repository
		pub := pk.Public()
		return []*jose.JSONWebKey{
			&pub,
		}, nil
	}, audience)
	if err != nil {
		panic(err)
	}

	// Verify and authenticate claims.
	claims, err := verifier.Verify(context.Background(), clientID, assertion)
	if err != nil {
		panic(err)
	}

	// Output: 123456789
	fmt.Printf("%s\n", claims.Subject)
}
