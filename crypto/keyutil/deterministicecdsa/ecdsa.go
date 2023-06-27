// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package deterministicecdsa

// Golang 1.20 removed the deterministic ECDSA key geenration from a controlled random source feature.
//
// As recommended (https://github.com/golang/go/issues/38548#issuecomment-617409930), the code as been copied from Go
// 1.19.5 to restore the deterministic generation behavior.
// By default, the developer should use `crypto/ecdsa` from its go runtime and use this alternative for tests
// or specific usecases where the key generation is derivated from a computed random source.
//
// Copied from https://github.com/golang/go/blob/1e9ff255a130200fcc4ec5e911d28181fce947d5/src/crypto/ecdsa/ecdsa.go

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"io"
	"math/big"
)

var one = new(big.Int).SetInt64(1)

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.1.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	// Note that for P-521 this will actually be 63 bits more than the order, as
	// division rounds down, but the extra bit is inconsequential.
	b := make([]byte, params.N.BitLen()/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// GenerateKey generates a public and private key pair.
func GenerateKey(c elliptic.Curve, rand io.Reader) (*ecdsa.PrivateKey, error) {
	k, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}
