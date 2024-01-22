# httpclient

Package httpclient provides a SSRF-safe HTTP client implementation.

## Variables

DefaultAuthorizer exposes the default authorizer instance.

```golang
var DefaultAuthorizer = &ssrfAuthorizer{}
```

DefaultClient represents a safe HTTP client instance.

```golang
var DefaultClient = Safe()
```

## Functions

### func [NewClient](client.go#L28)

`func NewClient(az Authorizer, opts ...Option) *http.Client`

NewClient is used to create a safe http client with the given authorizer
implementation.

### func [NewRequestFilter](interceptors.go#L20)

`func NewRequestFilter(az Authorizer, next http.RoundTripper) http.RoundTripper`

NewRequestFilter set up a request interceptor to authorize the request before
being sent by the client.

### func [NewResponseFilter](interceptors.go#L47)

`func NewResponseFilter(az Authorizer, next http.RoundTripper) http.RoundTripper`

NewResponseFilter set up a response interceptor to authorize a response from
a client.

### func [Safe](client.go#L22)

`func Safe(opts ...Option) *http.Client`

Safe returns a safe HTTP client with the default authorizer
implementation.

```golang
c := Safe()

// Query AWS Metatadata
r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
if err != nil {
    panic(err)
}

resp, err := c.Do(r)
if resp != nil {
    defer resp.Body.Close()
}
```

 Output:

```
Get "http://169.254.169.254/latest/meta-data/": response filter round trip failed: request filter round trip failed: dial tcp 169.254.169.254:80: tcp4/169.254.169.254:80 is not authorized by the client: "169.254.169.254" address is link local unicast
```

### func [UnSafe](client.go#L16)

`func UnSafe(opts ...Option) *http.Client`

UnSafe returns a HTTP client with default transport settings only.

```golang
// Create a fake http server
mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, "", http.StatusFound)
}))

c := UnSafe(
    // Reduce timeout
    WithTimeout(3*time.Second),
    // Disable keep alives
    WithDisableKeepAlives(true),
    // Default for unsafe
    WithDisableRequestFilter(true),
    // Default for unsafe
    WithDisableResponseFilter(true),
    // Enable follow redirect
    WithFollowRedirect(true),
    // Change max redirection count
    WithMaxRedirectionCount(2),
)

// Query AWS Metatadata
r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, mockServer.URL, nil)
if err != nil {
    panic(err)
}

resp, err := c.Do(r)
if resp != nil {
    defer resp.Body.Close()
}
```

 Output:

```
Get "/": stopped after 2 redirects
```

## Types

### type [Authorizer](api.go#L8)

`type Authorizer interface { ... }`

Authorizer describes socket level authorization gates.

### type [Option](options.go#L11)

`type Option func(*options)`

Option represents http client functional option pattern type.

#### func [WithDisableKeepAlives](options.go#L32)

`func WithDisableKeepAlives(value bool) Option`

WithDisableKeepAlives disables the keep alive feature.

#### func [WithDisableRequestFilter](options.go#L39)

`func WithDisableRequestFilter(value bool) Option`

WithDisableRequestFilter disables the request filtering feature.

#### func [WithDisableResponseFilter](options.go#L46)

`func WithDisableResponseFilter(value bool) Option`

WithDisableResponseFilter disables the response filtering feature.

#### func [WithFollowRedirect](options.go#L53)

`func WithFollowRedirect(value bool) Option`

WithFollowRedirect disables the redirection follower feature.

#### func [WithMaxRedirectionCount](options.go#L61)

`func WithMaxRedirectionCount(value int) Option`

WithMaxRedirectionCount sets the maximum redirection count before returning
an error.

#### func [WithTLSClientConfig](options.go#L68)

`func WithTLSClientConfig(value *tls.Config) Option`

WithTLSClientConfig sets the HTTP client TLS configuration to use for connection.

#### func [WithTLSDialer](options.go#L75)

`func WithTLSDialer(dialer func(context.Context, string, string) (net.Conn, error)) Option`

WithTLSDialer sets the TLS Dialer function to use to establish the connection.

#### func [WithTimeout](options.go#L25)

`func WithTimeout(value time.Duration) Option`

WithTimeout sets the client timeout.

## Sub Packages

* [mock](./mock): Package mock is a generated GoMock package.

