package safehttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

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

// Server is a safe wrapper for a standard HTTP server.
// It requires setting Mux before calling Serve.
// Changing any of the fields after the server has been started is a no-op.
//
// Ensures sane and secure values of `net/http.Server` struct:
//
//   - Set the `ReadTimeout` to `10s`
//   - Set the `ReadHeaderTimeout` to `5s`
//   - Let WriteTimeout to be handled by the request handler
//   - Set the `IdleTimeout` to `120s`
//   - Set the `MaxHeaderBytes` to `64kiB` (Go default to 1MiB)
//   - Enforce TLS v1.2 as minimal supported version if `*tls.Config` is used
//   - Provide a server shutdown function registry helper to trigger specific process when the server shutdown is called
//   - Enforce a non-nil handler
type Server struct {
	// Addr optionally specifies the TCP address for the server to listen on,
	// in the form "host:port". If empty, ":http" (port 80) is used.
	// The service names are defined in RFC 6335 and assigned by IANA.
	// See net.Dial for details of the address format.
	Addr string

	// Mux is the ServeMux to use for the current server. A nil Mux is invalid.
	Mux http.Handler

	// ReadTimeout is the maximum duration for reading the entire
	// request, including the body.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out
	// writes of the response. It is reset whenever a new
	// request's header is read.
	WriteTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled.
	IdleTimeout time.Duration

	// MaxHeaderBytes controls the maximum number of bytes the
	// server will read parsing the request header's keys and
	// values, including the request line. It does not limit the
	// size of the request body.
	MaxHeaderBytes int

	// ReadHeaderTimeout is the amount of time allowed to read
	// request headers. The connection's read deadline is reset
	// after reading the headers and the Handler can decide what
	// is considered too slow for the body. If ReadHeaderTimeout
	// is zero, the value of ReadTimeout is used. If both are
	// zero, there is no timeout.
	ReadHeaderTimeout time.Duration

	// TLSConfig optionally provides a TLS configuration for use
	// by ServeTLS and ListenAndServeTLS. Note that this value is
	// cloned on serving, so it's not possible to modify the
	// configuration with methods like tls.Config.SetSessionTicketKeys.
	//
	// When the server is started the cloned configuration will be changed
	// to set the minimum TLS version to 1.2.
	TLSConfig *tls.Config

	// OnShutdown is a slice of functions to call on Shutdown.
	// This can be used to gracefully shutdown connections.
	OnShutdown []func()

	// DisableKeepAlives controls whether HTTP keep-alives should be disabled.
	DisableKeepAlives bool

	// srv is not nil after the server has been started
	srv atomic.Pointer[http.Server]
}

func (s *Server) buildServer() error {
	if s.srv.Load() != nil {
		// Server was already built
		return ErrServerAlreadyStarted
	}
	if s.Mux == nil {
		return fmt.Errorf("building server without a mux: %w", ErrInvalidServer)
	}

	srv := &http.Server{
		Addr:    s.Addr,
		Handler: s.Mux,
		// SlowLoris-like attack (https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/)
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		// Disconnect all idle clients (not responding to keep-alive pings)
		IdleTimeout: 120 * time.Second,
		// DoS on header memory allocations (default Go value is 1MB)
		MaxHeaderBytes: 64 * 1024, // 64KB
	}
	if s.ReadTimeout != 0 {
		srv.ReadTimeout = s.ReadTimeout
	}
	if s.ReadHeaderTimeout != 0 {
		if s.ReadHeaderTimeout > s.ReadTimeout {
			// Fallback to ReadTimeout
			srv.ReadHeaderTimeout = 0
		} else {
			srv.ReadHeaderTimeout = s.ReadHeaderTimeout
		}
	}
	if s.WriteTimeout != 0 {
		srv.WriteTimeout = s.WriteTimeout
	}
	if s.IdleTimeout != 0 {
		srv.IdleTimeout = s.IdleTimeout
	}
	if s.MaxHeaderBytes != 0 {
		srv.MaxHeaderBytes = s.MaxHeaderBytes
	}
	if s.TLSConfig != nil {
		cfg := s.TLSConfig.Clone()
		if cfg == nil {
			return fmt.Errorf("unable to clone TLS config: %w", ErrInvalidServer)
		}
		// Ensure TLSv1.2 version as server
		cfg.MinVersion = tls.VersionTLS12
		srv.TLSConfig = cfg
	}
	for _, f := range s.OnShutdown {
		srv.RegisterOnShutdown(f)
	}
	if s.DisableKeepAlives {
		srv.SetKeepAlivesEnabled(false)
	}
	s.srv.Store(srv)

	return nil
}

// ListenAndServe is a wrapper for https://golang.org/pkg/net/http/#Server.ListenAndServe
//
//nolint:wrapcheck
func (s *Server) ListenAndServe() error {
	if err := s.buildServer(); err != nil {
		return fmt.Errorf("unable to build server instance: %w", err)
	}
	return s.srv.Load().ListenAndServe()
}

// ListenAndServeTLS is a wrapper for https://golang.org/pkg/net/http/#Server.ListenAndServeTLS
//
//nolint:wrapcheck
func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	if err := s.buildServer(); err != nil {
		return fmt.Errorf("unable to build server instance: %w", err)
	}
	return s.srv.Load().ListenAndServeTLS(certFile, keyFile)
}

// Serve is a wrapper for https://golang.org/pkg/net/http/#Server.Serve
//
//nolint:wrapcheck
func (s *Server) Serve(l net.Listener) error {
	if err := s.buildServer(); err != nil {
		return fmt.Errorf("unable to build server instance: %w", err)
	}
	return s.srv.Load().Serve(l)
}

// ServeTLS is a wrapper for https://golang.org/pkg/net/http/#Server.ServeTLS
//
//nolint:wrapcheck
func (s *Server) ServeTLS(l net.Listener, certFile, keyFile string) error {
	if err := s.buildServer(); err != nil {
		return fmt.Errorf("unable to build server instance: %w", err)
	}
	return s.srv.Load().ServeTLS(l, certFile, keyFile)
}

// Shutdown is a wrapper for https://golang.org/pkg/net/http/#Server.Shutdown
//
//nolint:wrapcheck
func (s *Server) Shutdown(ctx context.Context) error {
	if s.srv.Load() == nil {
		return fmt.Errorf("unable to shutdown the server: %w", ErrServerIsNotStarted)
	}
	return s.srv.Load().Shutdown(ctx)
}

// Close is a wrapper for https://golang.org/pkg/net/http/#Server.Close
//
//nolint:wrapcheck
func (s *Server) Close() error {
	if s.srv.Load() == nil {
		return fmt.Errorf("unable to close the server: %w", ErrServerIsNotStarted)
	}
	return s.srv.Load().Close()
}
