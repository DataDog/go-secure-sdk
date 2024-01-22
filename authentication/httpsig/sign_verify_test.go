package httpsig

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

var clientPrivateJWK = []byte(`{ "kty": "EC", "d": "74RBzgBeUoWhm3UgrNtyyM-nPfnc-Gqnf6PJHXFOYhw", "use": "sig", "kid": "dpop", "crv": "P-256", "x": "ZThHZviy98QoHBmiFuh6qeRFlU9qZJQcHLECNTiyaj8", "y": "_PC72xTaT4mMRsdK8YVK00owFH1SsT25tbmRBhxlIGM", "alg": "ES256"}`)

func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	// Decode the key as a JWK
	var pk jose.JSONWebKey
	require.NoError(t, json.Unmarshal(clientPrivateJWK, &pk))
	pub := pk.Public()

	t.Run("POST with body", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "https://webhooks.datadoghq.com/123456", bytes.NewReader([]byte(`{}`)))
		req.Header.Add("Authorization", "Bearer 0123456789")

		// Sign the request
		signedReq, err := sign(req, req.Body, &pk)
		require.NoError(t, err)
		require.NotNil(t, signedReq)

		// Create a verifier
		v := NewRequestVerifier(signedReq)
		require.NoError(t, v.Verify(&pub))
	})

	t.Run("GET", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "https://signed.datadoghq.com/dl/agent", nil)

		// Sign the request
		signedReq, err := sign(req, nil, &pk)
		require.NoError(t, err)
		require.NotNil(t, signedReq)

		// Create a verifier
		v := NewRequestVerifier(signedReq)
		require.NoError(t, v.Verify(&pub))
	})
}
