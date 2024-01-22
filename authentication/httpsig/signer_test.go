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

func TestSigner(t *testing.T) {
	t.Parallel()

	// Decode the key as a JWK
	var pk jose.JSONWebKey
	require.NoError(t, json.Unmarshal(clientPrivateJWK, &pk))
	pub := pk.Public()

	t.Run("nil key", func(t *testing.T) {
		t.Parallel()

		body := []byte(`{}`)
		req := httptest.NewRequest(http.MethodPost, "https://webhooks.datadoghq.com/123456", bytes.NewReader(body))
		require.NotNil(t, req)

		signer, err := NewRequestSigner(nil)
		require.Error(t, err)
		require.Nil(t, signer)
	})

	t.Run("invalid key", func(t *testing.T) {
		t.Parallel()

		body := []byte(`{}`)
		req := httptest.NewRequest(http.MethodPost, "https://webhooks.datadoghq.com/123456", bytes.NewReader(body))
		require.NotNil(t, req)

		signer, err := NewRequestSigner(&pub)
		require.Error(t, err)
		require.Nil(t, signer)
	})

	t.Run("invalid signer", func(t *testing.T) {
		t.Parallel()

		body := []byte(`{}`)
		req := httptest.NewRequest(http.MethodPost, "https://webhooks.datadoghq.com/123456", bytes.NewReader(body))
		require.NotNil(t, req)

		signer, err := NewRequestSigner(&jose.JSONWebKey{})
		require.NoError(t, err)

		signedReq, err := signer.Sign(req, bytes.NewReader(body))
		require.Error(t, err)
		require.Nil(t, signedReq)
	})

	t.Run("nil request", func(t *testing.T) {
		t.Parallel()

		body := []byte(`{}`)
		req := httptest.NewRequest(http.MethodPost, "https://webhooks.datadoghq.com/123456", bytes.NewReader(body))
		require.NotNil(t, req)

		signer, err := NewRequestSigner(&pk)
		require.NoError(t, err)

		signedReq, err := signer.Sign(nil, bytes.NewReader(body))
		require.Error(t, err)
		require.Nil(t, signedReq)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		body := []byte(`{}`)
		req := httptest.NewRequest(http.MethodPost, "https://webhooks.datadoghq.com/123456", bytes.NewReader(body))
		require.NotNil(t, req)

		signer, err := NewRequestSigner(&pk)
		require.NoError(t, err)

		signedReq, err := signer.Sign(req, bytes.NewReader(body))
		require.NoError(t, err)
		require.NotNil(t, signedReq)

		require.NotEmpty(t, signedReq.Header.Get("signature"))
		require.NotEmpty(t, signedReq.Header.Get("signature-input"))
	})
}
