// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package hashutil

import (
	"crypto"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/DataDog/go-secure-sdk/ioutil"
)

// Hash consumes the input reader content to produce a raw checksum from the
// given crypto.Hash implementation.
func Hash(r io.Reader, hf crypto.Hash) ([]byte, error) {
	// Check arguments
	if r == nil {
		return nil, fmt.Errorf("reader must not be nil")
	}

	// Prepare the hash function
	if !hf.Available() {
		return nil, fmt.Errorf("%q hash function is not available", hf.String())
	}

	// Create hash function instance
	h := hf.New()
	if h == nil {
		return nil, errors.New("hash function returned a nil instance")
	}

	// Copy content from the reader to the hasher
	if _, err := ioutil.LimitCopy(h, r, maxHashContent); err != nil {
		if !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("unable to copy content for hashing purpose: %w", err)
		}
	}

	return h.Sum(nil), nil
}

// Hashes consumes the input rreader content to produce a raw checksum from the
// given crypto.Hash implementation collection.
func Hashes(r io.Reader, hbs ...crypto.Hash) (map[crypto.Hash][]byte, error) {
	// Check arguments
	if r == nil {
		return nil, fmt.Errorf("reader must not be nil")
	}

	// Prepare all hash writers
	var (
		hashers = map[crypto.Hash]hash.Hash{}
		writers []io.Writer
	)
	for _, hb := range hbs {
		if hb.Available() {
			hashers[hb] = hb.New()
			writers = append(writers, hashers[hb])
		}
	}

	// Ensure writer count
	if len(writers) == 0 {
		return nil, errors.New("no available hash identified for hashing the content")
	}

	// creates a multiplexer Writer object that will duplicate all write
	// operations when copying data from source into all different hashing algorithms
	// at the same time
	multiWriter := io.MultiWriter(writers...)

	// Copy content from the reader to the hasher
	if _, err := ioutil.LimitCopy(multiWriter, r, maxHashContent); err != nil {
		if !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("unable to copy content for hashing purpose: %w", err)
		}
	}

	// Prepare response
	results := map[crypto.Hash][]byte{}
	for c, h := range hashers {
		results[c] = h.Sum(nil)
	}

	return results, nil
}
