package httpsig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/yaronf/httpsign"
	"gopkg.in/square/go-jose.v2"
)

// NewRequestVerifier instantiates an HTTP request verifier for the given request.
func NewRequestVerifier(req *http.Request, opts ...VerifyOption) RequestVerifier {
	// Compute verifier options
	dopts := &verifyOptions{
		maxBodySize: uint64(maxBodySize),
	}
	for _, o := range opts {
		o(dopts)
	}

	return &requestVerifier{
		dopts: dopts,
		req:   req,
	}
}

// -----------------------------------------------------------------------------

type requestVerifier struct {
	dopts *verifyOptions
	req   *http.Request
}

func (v *requestVerifier) Verify(pub *jose.JSONWebKey) error {
	// Check arguments
	if pub == nil {
		return errors.New("unable to verify with a nil key")
	}
	if !pub.IsPublic() {
		return errors.New("unable to verify without a public key")
	}

	// Default fields to verified (don't let the fields be driven by the
	// signature-parameters to mitigate signature malleability issues.)
	//
	// For derived component definitions - https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-16#name-derived-components
	fields := httpsign.Headers("@method", "@target-uri")

	// Has authorization header in the request
	if v.req.Header.Get("authorization") != "" {
		fields.AddHeader("authorization")
	}

	// has a request body
	if v.req.Body != nil {
		// Drain request body
		bodyRaw, err := io.ReadAll(io.LimitReader(v.req.Body, int64(v.dopts.maxBodySize+1)))
		if err != nil {
			return fmt.Errorf("unable to read request body: %w", err)
		}
		if len(bodyRaw) > int(v.dopts.maxBodySize) {
			return errors.New("request body is too large to be processed")
		}

		// Re-assign body content
		v.req.Body = io.NopCloser(bytes.NewBuffer(bodyRaw))

		// The request has a body, enforce content-digest computation
		if len(bodyRaw) > 0 {
			fields.AddHeader("content-digest")
		}
	}

	// Initialize a verifier
	verifier, err := httpsign.NewJWSVerifier(
		jwa.SignatureAlgorithm(pub.Algorithm),
		pub.Key,
		pub.KeyID,
		nil,
		fields,
	)
	if err != nil {
		return fmt.Errorf("unable to initialize the request verifier: %w", err)
	}

	// Verify the request signature
	if err := httpsign.VerifyRequest(defaultSignatureName, *verifier, v.req); err != nil {
		return fmt.Errorf("unable to validate request signature: %w", err)
	}

	return nil
}
