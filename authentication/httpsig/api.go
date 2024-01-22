package httpsig

import (
	"io"
	"net/http"

	"gopkg.in/square/go-jose.v2"
)

const defaultSignatureName = "ddsig1"

var maxBodySize int64 = 100 << 20 // 100MB

// RequestSigner describes HTTP request signer contract.
type RequestSigner interface {
	Sign(req *http.Request, body io.Reader) (*http.Request, error)
}

// RequestVerifier describes HTTP request verifier contract.
type RequestVerifier interface {
	Verify(pub *jose.JSONWebKey) error
}
