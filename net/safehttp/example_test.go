// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
)

func ExampleServer() {
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
}

func ExampleNewCookie() {
	mux := &http.ServeMux{}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		c := NewCookie("uid", "123456789")
		w.Header().Add("Set-Cookie", c.String())
	})
}
