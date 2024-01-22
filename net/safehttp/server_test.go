package safehttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/net/httpclient"
)

type listeningServer struct {
	listener     net.Listener
	server       *Server
	serverExited chan struct{}
}

// startServer returns a listeningServer listening on a random port. Call shutdownAndWait() to stop.
func startServer(mux *http.ServeMux) (*listeningServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	listening := &listeningServer{
		listener: listener,
		server: &Server{
			Mux: mux,
		},
		serverExited: make(chan struct{}),
	}
	go func() {
		if err := listening.server.Serve(listener); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				panic(fmt.Sprintf("safehttp.Server exited with unexpected error: %s", err))
			}
		}
		close(listening.serverExited)
	}()

	return listening, nil
}

func (l *listeningServer) addr() string {
	return l.listener.Addr().String()
}

func (l *listeningServer) shutdownAndWait() error {
	err := l.server.Shutdown(context.Background())
	if err != nil {
		return err
	}
	<-l.serverExited
	return nil
}

func (l *listeningServer) waitForStarted() error {
	// this is inherently racy, so we retry with some sleep
	// We can't make an HTTP request: it synchronizes with server startup
	const maxAttempts = 5
	// initial sleep to let the server to start
	time.Sleep(time.Millisecond)
	for i := 0; i < maxAttempts; i++ {
		// TODO: Don't check private internals?
		if l.server.srv.Load() != nil {
			return nil
		}
		if i < maxAttempts-1 {
			time.Sleep((10 * time.Millisecond) * time.Duration(i+1))
		}
	}
	return fmt.Errorf("server did not start after %d attempts", maxAttempts)
}

func TestServer(t *testing.T) {
	t.Parallel()

	mux := &http.ServeMux{}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	})
	listening, err := startServer(mux)
	require.NoError(t, err)

	defer func() {
		err := listening.shutdownAndWait()
		require.NoError(t, err)
	}()

	c := httpclient.UnSafe()
	getURL := fmt.Sprintf("http://%s/", listening.addr())
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, getURL, nil)
	require.NoError(t, err)

	resp, err := c.Do(req)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	err = resp.Body.Close()
	require.NoError(t, err)
}

// Ensure there are no races between serving and shutdown so it can be used in tests.
func TestServerShutdownRace(t *testing.T) {
	t.Parallel()

	listening, err := startServer(&http.ServeMux{})
	require.NoError(t, err)
	defer func() {
		err := listening.shutdownAndWait()
		require.NoError(t, err)
	}()

	listening.waitForStarted()
	err = listening.server.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestServer_BuildTwice(t *testing.T) {
	t.Parallel()

	// Create a server
	s := &Server{
		Mux: &http.ServeMux{},
	}

	err := s.buildServer()
	require.NoError(t, err)

	err = s.buildServer()
	require.ErrorIs(t, err, ErrServerAlreadyStarted)
}

func TestServer_NilMux(t *testing.T) {
	t.Parallel()

	// Create a random port listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// Create a server
	s := &Server{
		Mux: nil,
	}

	err = s.Serve(l)
	require.Error(t, err)
	require.ErrorContains(t, err, "building server without a mux")
	require.ErrorIs(t, err, ErrInvalidServer)
}

func TestServer_AlreadyStarted(t *testing.T) {
	t.Parallel()

	listening, err := startServer(&http.ServeMux{})
	require.NoError(t, err)
	err = listening.waitForStarted()
	require.NoError(t, err)

	t.Run("Build", func(t *testing.T) {
		t.Parallel()

		err := listening.server.buildServer()
		require.ErrorIs(t, err, ErrServerAlreadyStarted)
	})

	t.Run("ListenAndServe", func(t *testing.T) {
		t.Parallel()

		err := listening.server.ListenAndServe()
		require.ErrorIs(t, err, ErrServerAlreadyStarted)
	})

	t.Run("ListenAndServeTLS", func(t *testing.T) {
		t.Parallel()

		err := listening.server.ListenAndServeTLS("", "")
		require.ErrorIs(t, err, ErrServerAlreadyStarted)
	})

	t.Run("Serve", func(t *testing.T) {
		t.Parallel()

		err := listening.server.Serve(nil)
		require.ErrorIs(t, err, ErrServerAlreadyStarted)
	})

	t.Run("ServeTLS", func(t *testing.T) {
		t.Parallel()

		err := listening.server.ServeTLS(nil, "", "")
		require.ErrorIs(t, err, ErrServerAlreadyStarted)
	})
}

func TestServer_NotStartedError(t *testing.T) {
	t.Parallel()

	// Create a server
	s := &Server{
		Mux: &http.ServeMux{},
	}

	t.Run("Close", func(t *testing.T) {
		t.Parallel()

		err := s.Close()
		require.ErrorIs(t, err, ErrServerIsNotStarted)
	})

	t.Run("Shutdown", func(t *testing.T) {
		t.Parallel()

		err := s.Shutdown(context.Background())
		require.ErrorIs(t, err, ErrServerIsNotStarted)
	})
}
