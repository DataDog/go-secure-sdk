// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/net/httpclient"
)

//nolint:paralleltest,bodyclose
func TestServer(t *testing.T) {
	// Create a random port listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	mux := &http.ServeMux{}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	})

	// Create a server
	s := &Server{
		Mux: mux,
	}

	go func() {
		if err := s.Serve(l); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				require.NoError(t, err)
			}
		}
	}()
	defer func() {
		if err := s.Shutdown(context.Background()); err != nil {
			require.NoError(t, err)
		}
	}()

	c := httpclient.UnSafe()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("http://%s/", l.Addr().String()), nil)
	require.NoError(t, err)
	require.NotNil(t, req)

	resp, err := c.Do(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
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
	require.NoError(t, err)
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

	// Create a server
	s := &Server{
		// Fake start
		started: true,
		Mux:     &http.ServeMux{},
	}

	t.Run("Build", func(t *testing.T) {
		t.Parallel()

		err := s.buildServer()
		require.Error(t, err)
		require.ErrorIs(t, err, ErrServerAlreadyStarted)
	})

	t.Run("ListenAndServe", func(t *testing.T) {
		t.Parallel()

		err := s.ListenAndServe()
		require.Error(t, err)
		require.ErrorIs(t, err, ErrServerAlreadyStarted)
	})

	t.Run("ListenAndServeTLS", func(t *testing.T) {
		t.Parallel()

		err := s.ListenAndServeTLS("", "")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrServerAlreadyStarted)
	})

	t.Run("Serve", func(t *testing.T) {
		t.Parallel()

		err := s.Serve(nil)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrServerAlreadyStarted)
	})

	t.Run("ServeTLS", func(t *testing.T) {
		t.Parallel()

		err := s.ServeTLS(nil, "", "")
		require.Error(t, err)
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
		require.Error(t, err)
		require.ErrorIs(t, err, ErrServerIsNotStarted)
	})

	t.Run("Shutdown", func(t *testing.T) {
		t.Parallel()

		err := s.Shutdown(context.Background())
		require.Error(t, err)
		require.ErrorIs(t, err, ErrServerIsNotStarted)
	})
}
