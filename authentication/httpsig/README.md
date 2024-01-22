# httpsig

Package httpsig provides request authentication based on IETF HTTP message signature.

[https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-16](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-16)

## Types

### type [RequestSigner](api.go#L15)

`type RequestSigner interface { ... }`

RequestSigner describes HTTP request signer contract.

#### func [NewRequestSigner](signer.go#L16)

`func NewRequestSigner(key *jose.JSONWebKey) (RequestSigner, error)`

NewRequestSigner instantiates a new HTTP request signer using the provided
key to sign the requests.

```golang

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

```

### type [RequestVerifier](api.go#L20)

`type RequestVerifier interface { ... }`

RequestVerifier describes HTTP request verifier contract.

#### func [NewRequestVerifier](verifier.go#L16)

`func NewRequestVerifier(req *http.Request, opts ...VerifyOption) RequestVerifier`

NewRequestVerifier instantiates an HTTP request verifier for the given request.

### type [VerifyOption](options.go#L4)

`type VerifyOption func(*verifyOptions)`

VerifyOption defines optional parameters for Verify operation.

#### func [WithMaxBodySize](options.go#L12)

`func WithMaxBodySize(value uint64) VerifyOption`

WithMaxBodySize sets the body size limit.
Default to 100MB.

