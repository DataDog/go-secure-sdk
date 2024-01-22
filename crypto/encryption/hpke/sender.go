// SPDX-FileCopyrightText: 2023 Thibault NORMAND <me@zenithar.org>
//
// SPDX-License-Identifier: Apache-2.0 AND MIT

package hpke

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
)

// Sender describes message sender contract.
type Sender interface {
	SetupBase() ([]byte, Sealer, error)
	SetupPSK(psk, pskID []byte) ([]byte, Sealer, error)
	SetupAuth(skS *ecdh.PrivateKey) ([]byte, Sealer, error)
	SetupAuthPSK(psk, pskID []byte, skS *ecdh.PrivateKey) ([]byte, Sealer, error)
}

// Sealer encrypts a plaintext using an AEAD encryption.
type Sealer interface {
	Exporter

	// Seal encrypts a given plaintext a plaintext with associated data.
	// The nonce is managed internally.
	Seal(pt, aad []byte) (ct []byte, err error)
}

type sender struct {
	*cipherSuite
	pkR  *ecdh.PublicKey
	info []byte
}

func (s *sender) SetupBase() ([]byte, Sealer, error) {
	return s.setupBase(rand.Reader)
}

func (s *sender) setupBase(r io.Reader) ([]byte, Sealer, error) {
	// Generate a seed
	seed := make([]byte, s.kemID.Scheme().PrivateKeySize())
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, nil, fmt.Errorf("unable to generate encapsulation seed: %w", err)
	}

	// shared_secret, enc = Encap(pkR)
	ss, enc, err := s.kemID.Scheme().EncapsulateDeterministically(seed, s.pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("sender: %w", err)
	}

	ctx, err := s.keySchedule(modeBase, ss, s.info, defaultPSK, defaultPSKID)
	if err != nil {
		return nil, nil, fmt.Errorf("sender: unable to initialize key schedule: %w", err)
	}

	return enc, ctx, nil
}

func (s *sender) SetupPSK(psk, pskID []byte) ([]byte, Sealer, error) {
	return s.setupPSK(rand.Reader, psk, pskID)
}

func (s *sender) setupPSK(r io.Reader, psk, pskID []byte) ([]byte, Sealer, error) {
	// Generate a seed
	seed := make([]byte, s.kemID.Scheme().PrivateKeySize())
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, nil, fmt.Errorf("unable to generate encapsulation seed: %w", err)
	}

	// shared_secret, enc = Encap(pkR)
	ss, enc, err := s.kemID.Scheme().EncapsulateDeterministically(seed, s.pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("sender: %w", err)
	}

	ctx, err := s.keySchedule(modePsk, ss, s.info, psk, pskID)
	if err != nil {
		return nil, nil, fmt.Errorf("sender: unable to initialize key schedule: %w", err)
	}

	return enc, ctx, nil
}

func (s *sender) SetupAuth(skS *ecdh.PrivateKey) ([]byte, Sealer, error) {
	return s.setupAuth(rand.Reader, skS)
}

func (s *sender) setupAuth(r io.Reader, skS *ecdh.PrivateKey) ([]byte, Sealer, error) {
	// Generate a seed
	seed := make([]byte, s.kemID.Scheme().PrivateKeySize())
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, nil, fmt.Errorf("unable to generate encapsulation seed: %w", err)
	}

	// shared_secret, enc = AuthEncap(pkR, skS)
	ss, enc, err := s.kemID.Scheme().AuthEncapsulateDeterministically(seed, s.pkR, skS)
	if err != nil {
		return nil, nil, fmt.Errorf("sender: %w", err)
	}

	ctx, err := s.keySchedule(modeAuth, ss, s.info, defaultPSK, defaultPSKID)
	if err != nil {
		return nil, nil, fmt.Errorf("sender: unable to initialize key schedule: %w", err)
	}

	return enc, ctx, nil
}

func (s *sender) SetupAuthPSK(psk, pskID []byte, skS *ecdh.PrivateKey) ([]byte, Sealer, error) {
	return s.setupAuthPSK(rand.Reader, psk, pskID, skS)
}

func (s *sender) setupAuthPSK(r io.Reader, psk, pskID []byte, skS *ecdh.PrivateKey) ([]byte, Sealer, error) {
	// Generate a seed
	seed := make([]byte, s.kemID.Scheme().PrivateKeySize())
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, nil, fmt.Errorf("unable to generate encapsulation seed: %w", err)
	}

	// shared_secret, enc = AuthEncap(pkR, skS)
	ss, enc, err := s.kemID.Scheme().AuthEncapsulateDeterministically(seed, s.pkR, skS)
	if err != nil {
		return nil, nil, fmt.Errorf("sender: %w", err)
	}

	ctx, err := s.keySchedule(modeAuthPsk, ss, s.info, psk, pskID)
	if err != nil {
		return nil, nil, fmt.Errorf("sender: unable to initialize key schedule: %w", err)
	}

	return enc, ctx, nil
}
