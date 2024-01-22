// SPDX-FileCopyrightText: 2023 Thibault NORMAND <me@zenithar.org>
//
// SPDX-License-Identifier: Apache-2.0 AND MIT

package hpke

import (
	"crypto/ecdh"
	"fmt"
)

// Receiver describes message receiver contract.
type Receiver interface {
	SetupBase(enc []byte) (Opener, error)
	SetupPSK(enc, psk, pskID []byte) (Opener, error)
	SetupAuth(enc []byte, pkS *ecdh.PublicKey) (Opener, error)
	SetupAuthPSK(enc, psk, pskID []byte, pkS *ecdh.PublicKey) (Opener, error)
}

// Opener decrypts a ciphertext using an AEAD encryption.
type Opener interface {
	Exporter

	// Open tries to authenticate and decrypt a ciphertext with associated
	// additional data. The nonce is handled internally.
	Open(ct, aad []byte) (pt []byte, err error)
}

type receiver struct {
	*cipherSuite
	skR  *ecdh.PrivateKey
	info []byte
}

func (r *receiver) SetupBase(enc []byte) (Opener, error) {
	// shared_secret, enc = Encap(pkR)
	ss, err := r.kemID.Scheme().Decapsulate(enc, r.skR)
	if err != nil {
		return nil, fmt.Errorf("receiver: %w", err)
	}

	ctx, err := r.keySchedule(modeBase, ss, r.info, defaultPSK, defaultPSKID)
	if err != nil {
		return nil, fmt.Errorf("receiver: unable to initialize key schedule: %w", err)
	}

	return ctx, nil
}

func (r *receiver) SetupPSK(enc, psk, pskID []byte) (Opener, error) {
	// shared_secret, enc = Encap(pkR)
	ss, err := r.kemID.Scheme().Decapsulate(enc, r.skR)
	if err != nil {
		return nil, fmt.Errorf("receiver: %w", err)
	}

	ctx, err := r.keySchedule(modePsk, ss, r.info, psk, pskID)
	if err != nil {
		return nil, fmt.Errorf("receiver: unable to initialize key schedule: %w", err)
	}

	return ctx, nil
}

func (r *receiver) SetupAuth(enc []byte, pkS *ecdh.PublicKey) (Opener, error) {
	// shared_secret = AuthDecap(enc, skR, pkS)
	ss, err := r.kemID.Scheme().AuthDecapsulate(enc, r.skR, pkS)
	if err != nil {
		return nil, fmt.Errorf("receiver: %w", err)
	}

	ctx, err := r.keySchedule(modeAuth, ss, r.info, defaultPSK, defaultPSKID)
	if err != nil {
		return nil, fmt.Errorf("receiver: unable to initialize key schedule: %w", err)
	}

	return ctx, nil
}

func (r *receiver) SetupAuthPSK(enc, psk, pskID []byte, pkS *ecdh.PublicKey) (Opener, error) {
	// shared_secret = AuthDecap(enc, skR, pkS)
	ss, err := r.kemID.Scheme().AuthDecapsulate(enc, r.skR, pkS)
	if err != nil {
		return nil, fmt.Errorf("receiver: %w", err)
	}

	ctx, err := r.keySchedule(modeAuthPsk, ss, r.info, psk, pskID)
	if err != nil {
		return nil, fmt.Errorf("receiver: unable to initialize key schedule: %w", err)
	}

	return ctx, nil
}
