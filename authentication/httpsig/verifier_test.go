package httpsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

type errorReader string

func (b errorReader) Read([]byte) (int, error) {
	return 0, errors.New(string(b))
}

func TestVerifier(t *testing.T) {
	t.Parallel()

	// Decode the key as a JWK
	var pk jose.JSONWebKey
	require.NoError(t, json.Unmarshal(clientPrivateJWK, &pk))
	pub := pk.Public()

	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer, err := NewRequestSigner(&pk)
	require.NoError(t, err)
	require.NotNil(t, signer)

	t.Run("nil key", func(t *testing.T) {
		t.Parallel()

		body := []byte(`{}`)
		req := httptest.NewRequest(http.MethodPost, "https://webhooks.datadoghq.com/123456", bytes.NewReader(body))
		require.NotNil(t, req)

		signedReq, err := signer.Sign(req, bytes.NewReader(body))
		require.NoError(t, err)
		require.NotNil(t, signedReq)

		verifier := NewRequestVerifier(signedReq)
		err = verifier.Verify(nil)
		require.Error(t, err)
	})

	t.Run("private key", func(t *testing.T) {
		t.Parallel()

		body := []byte(`{}`)
		req := httptest.NewRequest(http.MethodPost, "https://webhooks.datadoghq.com/123456", bytes.NewReader(body))
		require.NotNil(t, req)

		signedReq, err := signer.Sign(req, bytes.NewReader(body))
		require.NoError(t, err)
		require.NotNil(t, signedReq)

		verifier := NewRequestVerifier(signedReq)
		err = verifier.Verify(&pk)
		require.Error(t, err)
	})

	t.Run("verification error", func(t *testing.T) {
		t.Parallel()

		body := []byte(`{}`)
		req := httptest.NewRequest(http.MethodPost, "https://webhooks.datadoghq.com/123456", bytes.NewReader(body))
		require.NotNil(t, req)

		signedReq, err := signer.Sign(req, bytes.NewReader(body))
		require.NoError(t, err)
		require.NotNil(t, signedReq)

		verifier := NewRequestVerifier(signedReq)
		err = verifier.Verify(&jose.JSONWebKey{
			Algorithm: string(jose.EdDSA),
			KeyID:     "987456321",
			Key:       pub2,
		})
		require.ErrorContains(t, err, "unable to validate request signature")
	})

	t.Run("body error", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "https://webhooks.datadoghq.com/123456", errorReader("bad body"))
		require.NotNil(t, req)

		verifier := NewRequestVerifier(req)
		err = verifier.Verify(&pub)
		require.ErrorContains(t, err, "bad body")
	})

	t.Run("body too large", func(t *testing.T) {
		t.Parallel()

		body := []byte(`{}`)
		req := httptest.NewRequest(http.MethodPost, "https://webhooks.datadoghq.com/123456", bytes.NewReader(body))
		require.NotNil(t, req)

		signedReq, err := signer.Sign(req, bytes.NewReader(body))
		require.NoError(t, err)
		require.NotNil(t, signedReq)

		verifier := NewRequestVerifier(signedReq, WithMaxBodySize(1))
		err = verifier.Verify(&pub)
		require.ErrorContains(t, err, "request body is too large to be processed")
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		body := []byte(`{}`)
		req := httptest.NewRequest(http.MethodPost, "https://webhooks.datadoghq.com/123456", bytes.NewReader(body))
		require.NotNil(t, req)

		signedReq, err := signer.Sign(req, bytes.NewReader(body))
		require.NoError(t, err)
		require.NotNil(t, signedReq)

		verifier := NewRequestVerifier(signedReq)
		require.NoError(t, verifier.Verify(&pub))
	})
}
