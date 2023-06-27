# safehttp

Package safehttp provides hardened HTTP related default functions.

## Variables

```golang
var (
    // ErrServerAlreadyStarted is raised when trying to start the server a second
    // time.
    ErrServerAlreadyStarted = errors.New("server already started")
    // ErrServerIsNotStarted is raised when the calle is trying to do operation
    // on a not started server.
    ErrServerIsNotStarted = errors.New("server not started")
    // ErrInvalidServer is raised when the server building process uses invalid
    // settings.
    ErrInvalidServer = errors.New("invalid server settings")
)
```

## Types

### type [Cookie](cookie.go#L16)

`type Cookie struct { ... }`

A Cookie represents an HTTP cookie as sent in the Set-Cookie header of an
HTTP response or the Cookie header of an HTTP request.

See [https://tools.ietf.org/html/rfc6265](https://tools.ietf.org/html/rfc6265) for details.

#### func [NewCookie](cookie.go#L29)

`func NewCookie(name, value string) *Cookie`

NewCookie creates a new Cookie with safe default settings.
Those safe defaults are:

Secure: true (if the framework is not in dev mode)
HttpOnly: true
SameSite: Lax

For more info about all the options, see:
[https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)

```golang

mux := &http.ServeMux{}
mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    c := NewCookie("uid", "123456789")
    w.Header().Add("Set-Cookie", c.String())
})

```

#### func (*Cookie) [DisableHTTPOnly](cookie.go#L107)

`func (c *Cookie) DisableHTTPOnly()`

DisableHTTPOnly disables the HttpOnly attribute.

#### func (*Cookie) [DisableSecure](cookie.go#L102)

`func (c *Cookie) DisableSecure()`

DisableSecure disables the secure attribute.

#### func (*Cookie) [Domain](cookie.go#L97)

`func (c *Cookie) Domain(domain string)`

Domain sets the domain attribute.

#### func (*Cookie) [MarkToDelete](cookie.go#L87)

`func (c *Cookie) MarkToDelete()`

MarkToDelete sets the cookie MaxAge to -1 which means that the cookie is
going to be removed from the client.

#### func (*Cookie) [Name](cookie.go#L112)

`func (c *Cookie) Name() string`

Name returns the name of the cookie.

#### func (*Cookie) [Path](cookie.go#L92)

`func (c *Cookie) Path(path string)`

Path sets the path attribute.

#### func (*Cookie) [SameSite](cookie.go#L65)

`func (c *Cookie) SameSite(s SameSite)`

SameSite sets the SameSite attribute.

#### func (*Cookie) [SetMaxAge](cookie.go#L81)

`func (c *Cookie) SetMaxAge(maxAge int)`

SetMaxAge sets the MaxAge attribute.

- MaxAge = 0 means no 'Max-Age' attribute specified.
- MaxAge < 0 means delete cookie now, equivalently 'Max-Age: 0'
- MaxAge > 0 means Max-Age attribute present and given in seconds

#### func (*Cookie) [String](cookie.go#L124)

`func (c *Cookie) String() string`

String returns the serialization of the cookie for use in a Set-Cookie
response header. If c is nil or c.Name() is invalid, the empty string is
returned.

#### func (*Cookie) [Value](cookie.go#L117)

`func (c *Cookie) Value() string`

Value returns the value of the cookie.

### type [SameSite](cookie.go#L51)

`type SameSite int`

SameSite allows a server to define a cookie attribute making it impossible for
the browser to send this cookie along with cross-site requests. The main
goal is to mitigate the risk of cross-origin information leakage, and provide
some protection against cross-site request forgery attacks.

See [https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00) for details.

#### Constants

```golang
const (
    // SameSiteLaxMode allows sending cookies with same-site requests and
    // cross-site top-level navigations.
    SameSiteLaxMode SameSite = iota + 1
    // SameSiteStrictMode allows sending cookie only with same-site requests.
    SameSiteStrictMode
    // SameSiteNoneMode allows sending cookies with all requests, including the
    // ones made cross-origin.
    SameSiteNoneMode
)
```

### type [Server](server.go#L42)

`type Server struct { ... }`

Server is a safe wrapper for a standard HTTP server.
The zero value is safe and ready to use and will apply safe defaults on serving.
Changing any of the fields after the server has been started is a no-op.

Ensure sane and secure values of `net/http.Server` struct:

- Set the `ReadTimeout` to `10s`
- Set the `ReadHeaderTimeout` to `5s`
- Let WriteTimeout to be handled by the request handler
- Set the `IdleTimeout` to `120s`
- Set the `MaxHeaderBytes` to `64kb` (Go default to 1Mb)
- Enforce TLS v1.2 as minimal supported version if `*tls.Config` is used
- Provide a server shutdown function registry helper to trigger specific process when the server shutdown is called
- Enforce a non-nil handler

```golang

// Create a random port listener
l, err := net.Listen("tcp", "127.0.0.1:0")
if err != nil {
    panic(err)
}

mux := &http.ServeMux{}
mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "OK")
})

// Create a server act as as a drop-in-replace to the net/http.Server.
s := &Server{
    Mux: mux,
}

go func() {
    if err := s.Serve(l); err != nil {
        if !errors.Is(err, http.ErrServerClosed) {
            panic(err)
        }
    }
}()
defer func() {
    if err := s.Shutdown(context.Background()); err != nil {
        panic(err)
    }
}()

```

#### func (*Server) [Clone](server.go#L160)

`func (s *Server) Clone() *Server`

Clone returns an unstarted deep copy of Server that can be re-configured and re-started.

#### func (*Server) [Close](server.go#L226)

`func (s *Server) Close() error`

Close is a wrapper for [https://golang.org/pkg/net/http/#Server.Close](https://golang.org/pkg/net/http/#Server.Close)

#### func (*Server) [ListenAndServe](server.go#L171)

`func (s *Server) ListenAndServe() error`

ListenAndServe is a wrapper for [https://golang.org/pkg/net/http/#Server.ListenAndServe](https://golang.org/pkg/net/http/#Server.ListenAndServe)

#### func (*Server) [ListenAndServeTLS](server.go#L182)

`func (s *Server) ListenAndServeTLS(certFile, keyFile string) error`

ListenAndServeTLS is a wrapper for [https://golang.org/pkg/net/http/#Server.ListenAndServeTLS](https://golang.org/pkg/net/http/#Server.ListenAndServeTLS)

#### func (*Server) [Serve](server.go#L193)

`func (s *Server) Serve(l net.Listener) error`

Serve is a wrapper for [https://golang.org/pkg/net/http/#Server.Serve](https://golang.org/pkg/net/http/#Server.Serve)

#### func (*Server) [ServeTLS](server.go#L204)

`func (s *Server) ServeTLS(l net.Listener, certFile, keyFile string) error`

ServeTLS is a wrapper for [https://golang.org/pkg/net/http/#Server.ServeTLS](https://golang.org/pkg/net/http/#Server.ServeTLS)

#### func (*Server) [Shutdown](server.go#L215)

`func (s *Server) Shutdown(ctx context.Context) error`

Shutdown is a wrapper for [https://golang.org/pkg/net/http/#Server.Shutdown](https://golang.org/pkg/net/http/#Server.Shutdown)

