package httpsig

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/yaronf/httpsign"
	"gopkg.in/square/go-jose.v2"
)

// NewRequestSigner instantiates a new HTTP request signer using the provided
// key to sign the requests.
func NewRequestSigner(key *jose.JSONWebKey) (RequestSigner, error) {
	// Check arguments
	switch {
	case key == nil:
		return nil, errors.New("the signing key must be provided")
	case key != nil && key.IsPublic():
		return nil, errors.New("the signing key must be a private key")
	default:
	}

	return &requestSigner{
		signingKey: key,
	}, nil
}

// -----------------------------------------------------------------------------

// Signer signs HTTP requests using http-signature.
type requestSigner struct {
	signingKey *jose.JSONWebKey
}

func (s *requestSigner) Sign(req *http.Request, body io.Reader) (*http.Request, error) {
	return sign(req, body, s.signingKey)
}

// -----------------------------------------------------------------------------

func sign(req *http.Request, bodyReader io.Reader, signingKey *jose.JSONWebKey) (*http.Request, error) {
	// Check arguments
	switch {
	case req == nil:
		return nil, errors.New("unable to sign nil request")
	case signingKey == nil:
		return nil, errors.New("the signing key must be provided")
	case signingKey != nil && signingKey.IsPublic():
		return nil, errors.New("the signing key must be a private key")
	default:
	}

	// Initialize httpsig
	conf := httpsign.NewSignConfig().SignAlg(false)

	// Set default fields to be signed
	//
	// For derived component definitions - https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-16#name-derived-components
	fields := httpsign.Headers("@method", "@target-uri")

	// If the request has a body
	if bodyReader != nil {
		body := io.NopCloser(bodyReader)

		// Compute content digest
		contentDigest, err := httpsign.GenerateContentDigestHeader(&body, []string{httpsign.DigestSha256})
		if err != nil {
			return nil, fmt.Errorf("unable to compute content-digest: %w", err)
		}

		// Assign content-digest to request headers
		req.Header.Add("content-digest", contentDigest)

		// Add content-digest to signature
		fields.AddHeader("content-digest")
	}

	// Protect authorization if given
	authorization := req.Header.Get("authorization")
	if authorization != "" {
		fields.AddHeader("authorization")
	}

	// Initialize a JWS signer
	signer, err := httpsign.NewJWSSigner(
		jwa.SignatureAlgorithm(signingKey.Algorithm),
		signingKey.KeyID,
		signingKey.Key,
		conf,
		fields,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize the request signer: %w", err)
	}

	// Sign the request
	sigInput, sig, err := httpsign.SignRequest(defaultSignatureName, *signer, req)
	if err != nil {
		return nil, fmt.Errorf("unable to sign the request: %w", err)
	}

	// Set the request headers
	req.Header.Set("Signature", sig)
	req.Header.Set("Signature-Input", sigInput)

	return req, nil
}
