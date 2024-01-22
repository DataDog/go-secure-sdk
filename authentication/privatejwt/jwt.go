package privatejwt

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/DataDog/go-secure-sdk/crypto/keyutil"
	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

var (
	// Ensure a slug-like assertion type identifier
	assertionTypeMatcher = regexp.MustCompile(`^[A-Za-z0-9-_]{2,50}$`)

	// Ensure sane default algorithms
	// https://www.scottbrady91.com/jose/jwts-which-signing-algorithm-should-i-use
	authorizedAlgorithms = []jose.SignatureAlgorithm{
		jose.EdDSA,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.RS256, jose.RS384, jose.RS512,
	}
)

// AssertionSigner instantiates a JWT client assertion signer.
//
// The signer key must be a private key encoded using JWK dedicated to signature
// purpose. This will produce an assertion from the ClientID identified as the
// issuer and the subject of this assertion. The generated assertion will be
// acceptable for the given expiration delay which must be bounded between
// 10 seconds and 10 minutes.
//
// EdDSA is disabled in FIPS mode.
// HMAC (HS*) based are disabled by design due to their lack of authentication.
// If the given key has a certificate, it will be embedded in the assertion.
func AssertionSigner(assertionType string, key *jose.JSONWebKey, clientID string, expiration time.Duration) (Signer, error) {
	// Validate parameters
	assertionType = strings.ToLower(strings.TrimSpace(assertionType))
	switch {
	case assertionType == "":
		return nil, errors.New("the assertion type identifier is mandatory")
	case !assertionTypeMatcher.MatchString(assertionType):
		return nil, errors.New("the assertion type identifier is invalid")
	case key == nil:
		return nil, errors.New("the signer key must not be blank")
	case key.IsPublic():
		return nil, errors.New("the signer key must not be a private key")
	case key.Use != "" && key.Use != "sig":
		return nil, errors.New("the key is not usable for signature purpose")
	case key.Algorithm == "":
		return nil, errors.New("the key algorithm must not be blank")
	case clientID == "":
		return nil, errors.New("the client identifier must not be blank")
	case expiration < minExpiration:
		return nil, fmt.Errorf("expiration must be greater than %s", minExpiration.String())
	case expiration > maxExpiration:
		return nil, fmt.Errorf("expiration must be lower than %s", maxExpiration.String())
	default:
	}

	// Check key algorithm
	if err := keyutil.IsUsable(key.Key); err != nil {
		return nil, fmt.Errorf("unable to initialize a signer: %w", err)
	}

	// Ensure authorized key algorithm
	authorized := false
	for _, alg := range authorizedAlgorithms {
		if key.Algorithm == string(alg) {
			authorized = true
			break
		}
	}
	if !authorized {
		return nil, fmt.Errorf("usage of %s is forbidden by design", key.Algorithm)
	}

	return &jwtSigner{
		privateKey:    key,
		clientID:      clientID,
		expiration:    expiration,
		assertionType: assertionType,
	}, nil
}

type verifierOptions struct {
	supportedAlgorithms []jose.SignatureAlgorithm
	caPool              *x509.CertPool
	ClientKeysResolver  ClientKeysResolver
}

// VerifierOption allows to customize the JWT verifier.
type VerifierOption func(*verifierOptions)

// WithSupportedAlgorithms allows to specify the supported signature algorithms
func WithSupportedAlgorithms(algorithms ...jose.SignatureAlgorithm) VerifierOption {
	return func(o *verifierOptions) {
		o.supportedAlgorithms = algorithms
	}
}

// WithCAPool allows to specify the CA pool to use to verify the certificate chain
func WithCAPool(pool *x509.CertPool) VerifierOption {
	return func(o *verifierOptions) {
		o.caPool = pool
	}
}

// WithClientKeysResolver allows to specify the client public keys resolver
func WithClientKeysResolver(resolver ClientKeysResolver) VerifierOption {
	return func(o *verifierOptions) {
		o.ClientKeysResolver = resolver
	}
}

// AssertionVerifier instantiates a JWT client assertion verifier.
//
// The assertion verifier can verify only one type of assertion, trying to
// verify any assertion generated with a different type will raise an error.
// The client's public keys are resolved at runtime from the ClientID. This
// operation could use caching for performance purpose.
// The assertion audience precises the assertion target, trying to verify an
// assertion with an audience mismatch will raise a verification error.
//
// To support progressive enhancements, the verification algorithm can support
// multiple signature algorithm will the system is migrating to new signature
// algorithms. Ensure this list to be as strict as possible.
//
// Authorized by design algorithms are:
// * Ed25519 keys => EdDSA
// * EC keys => ES256, ES384, ES512
// * RSA keys => PS256, PS384, PS512, RS256, RS384, RS512
//
// HMAC (HS*) based are disabled by design due to their lack of identity
// authentication ability.
//
// To support clockskew between servers, a default tolerance of 10s is applied
// to timestamp verification steps.
func AssertionVerifier(assertionType string, clientKeys ClientKeysResolver, audience string) (Verifier, error) {
	return RestrictedAssertionVerifier(assertionType, audience, WithClientKeysResolver(clientKeys), WithSupportedAlgorithms(authorizedAlgorithms...))
}

// RestrictedAssertionVerifier instantiates a JWT client assertion verifier with
// a restricted signature algorithm subset.
func RestrictedAssertionVerifier(assertionType, audience string, opts ...VerifierOption) (Verifier, error) {
	// Prepare options
	options := verifierOptions{
		supportedAlgorithms: authorizedAlgorithms,
		caPool:              nil,
	}
	for _, opt := range opts {
		opt(&options)
	}

	// Validate parameters
	assertionType = strings.ToLower(strings.TrimSpace(assertionType))
	switch {
	case assertionType == "":
		return nil, errors.New("the assertion type identifier is mandatory")
	case !assertionTypeMatcher.MatchString(assertionType):
		return nil, errors.New("the assertion type identifier is invalid")
	case audience == "":
		return nil, errors.New("audience must not be blank")
	case len(options.supportedAlgorithms) == 0:
		return nil, errors.New("at least one supported signature algorithm must be specified")
	case options.caPool != nil && options.caPool.Equal(x509.NewCertPool()):
		return nil, errors.New("the CA pool must not be empty if specified")
	case options.ClientKeysResolver == nil && options.caPool == nil:
		return nil, errors.New("client public keys resolver must not be nil if no CA pool is specified")
	default:
	}

	// Audience must be an URL
	u, err := url.ParseRequestURI(audience)
	if err != nil {
		return nil, fmt.Errorf("audience is not a valid URL: %w", err)
	}

	// Ensure authorized key algorithm
	for _, alg := range options.supportedAlgorithms {
		authorized := false
		for _, givenAlg := range authorizedAlgorithms {
			if alg == givenAlg {
				authorized = true
				break
			}
		}
		if !authorized {
			return nil, fmt.Errorf("usage of %s is forbidden by design", alg)
		}
	}

	return &jwtVerifier{
		audience:            u.String(),
		clientPublicKeys:    options.ClientKeysResolver,
		assertionType:       assertionType,
		supportedAlgorithms: options.supportedAlgorithms,
		clockProvider:       func() time.Time { return time.Now().UTC() },
		caPool:              options.caPool,
	}, nil
}

// -----------------------------------------------------------------------------

type jwtSigner struct {
	privateKey    *jose.JSONWebKey
	clientID      string
	expiration    time.Duration
	assertionType string
}

func (js *jwtSigner) Sign(_ context.Context, audience string) (string, error) {
	// Audience must be an URL
	u, err := url.ParseRequestURI(audience)
	if err != nil {
		return "", fmt.Errorf("audience is not a valid URL: %w", err)
	}

	// Generate token ID
	jti, err := randomness.Alphanumeric(jtiLength)
	if err != nil {
		return "", fmt.Errorf("unable to generate token identifier: %w", err)
	}

	// Get current timestamp
	now := time.Now().UTC()

	// Prepare claims
	claims := &Claims{
		Issuer:    js.clientID,
		Subject:   js.clientID,
		Audience:  u.String(),
		JTI:       jti,
		ExpiresAt: now.Add(js.expiration).UTC(),
		IssuedAt:  now,
	}

	// Create a JWT signer
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(js.privateKey.Algorithm),
		Key:       js.privateKey,
	}, &jose.SignerOptions{
		EmbedJWK: len(js.privateKey.Certificates) > 0,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderType: fmt.Sprintf("%s+jwt", js.assertionType),
		},
	})
	if err != nil {
		return "", fmt.Errorf("unable to initialize the assertion signer: %w", err)
	}

	// Forge the assertion
	t, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("unable to forge the final assertion: %w", err)
	}

	return t, nil
}

type jwtVerifier struct {
	audience            string
	clockProvider       func() time.Time
	clientPublicKeys    ClientKeysResolver
	assertionType       string
	supportedAlgorithms []jose.SignatureAlgorithm
	caPool              *x509.CertPool
}

func (jv *jwtVerifier) Verify(ctx context.Context, clientID, assertion string) (*Claims, error) {
	// Parse the given assertion
	t, err := jwt.ParseSigned(assertion)
	if err != nil {
		return nil, fmt.Errorf("unable to parse the given assertion: %w", err)
	}

	// Validate headers
	if len(t.Headers) != 1 {
		return nil, errors.New("invalid assertion format")
	}

	// Compute expected assertion type
	expectedAssertionType := fmt.Sprintf("%s+jwt", jv.assertionType)

	// Ensure assertion type presence
	typ, ok := t.Headers[0].ExtraHeaders[jose.HeaderType]
	if !ok || typ != expectedAssertionType {
		return nil, errors.New("invalid assertion")
	}

	// Get algorithm
	alg := t.Headers[0].Algorithm
	if alg == "none" {
		// Exclude immediately potentially attack attempt
		return nil, errors.New("invalid assertion")
	}

	// Compare with supported algorithm
	found := false
	for _, sigAlg := range jv.supportedAlgorithms {
		// Compare with existing algorithm
		if sigAlg == jose.SignatureAlgorithm(alg) {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("invalid assertion")
	}

	var (
		publicKeys []*jose.JSONWebKey
		errLookup  error
	)
	// If the token has an embedded key, the verifier has a CA pool and the key
	// has a certificate we can switch to self-contained verification mode.
	if embeddedKey := t.Headers[0].JSONWebKey; embeddedKey != nil && jv.caPool != nil && len(embeddedKey.Certificates) > 0 {
		// Extract the certificate
		// The first crtificate must be the leaf certificate associated to the
		// key used to sign the token.
		cert := embeddedKey.Certificates[0]

		// Check if the certificate is a CA.
		if cert == nil || cert != nil && cert.IsCA {
			return nil, errors.New("invalid assertion")
		}

		// Ensure public key match
		if err := keyutil.VerifyPublicKey(embeddedKey, cert.PublicKey); err != nil {
			return nil, fmt.Errorf("the JWK content has an unusal key for the context: %w", err)
		}

		// Verify the certificate chain
		chains, err := cert.Verify(x509.VerifyOptions{
			Roots: jv.caPool,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to verify the certificate chain: %w", err)
		}
		if len(chains) == 0 {
			return nil, errors.New("invalid assertion")
		}

		// Add the public key to the list
		publicKeys = append(publicKeys, embeddedKey)
	} else {
		// Resolve client public keys
		publicKeys, errLookup = jv.clientPublicKeys(ctx, clientID)
		if errLookup != nil {
			return nil, fmt.Errorf("unable to resolve client %q from the repository: %w", clientID, err)
		}
	}
	if len(publicKeys) == 0 {
		return nil, errors.New("invalid client authentication")
	}

	// Retrieve current timestamp
	now := jv.clockProvider()

	// Try to verify the assertion with all client public keys
	var claims Claims
	for _, pub := range publicKeys {
		// Skip invalid keys
		if pub == nil {
			continue
		}

		// Skip non-compliant keys
		if !pub.IsPublic() || alg != pub.Algorithm || pub.Use != "sig" {
			continue
		}

		// Check key algorithm
		if err := keyutil.IsUsable(pub); err != nil {
			continue
		}

		// Try to verify the signature
		if err := t.Claims(pub, &claims); err != nil {
			// Skip on error
			continue
		}

		// Validate claims
		if err := claims.Validate(clientID, jv.audience, now); err != nil {
			return nil, fmt.Errorf("invalid claim: %w", err)
		}

		// Return first match
		return &claims, nil
	}

	return nil, errors.New("authentication error")
}
