package kem

import (
	"crypto/ecdh"
	"errors"
	"fmt"
)

type keyDeriver func(*dhkem, []byte) (*ecdh.PublicKey, *ecdh.PrivateKey, error)

func ecDeriver(curve ecdh.Curve) keyDeriver {
	return func(kem *dhkem, seed []byte) (*ecdh.PublicKey, *ecdh.PrivateKey, error) {
		if len(seed) != int(kem.nSk) {
			return nil, nil, errors.New("invalid seed size")
		}

		dkpPrk := kem.labeledExtract([]byte(""), []byte("dkp_prk"), seed)
		counter := 0

		bitMask := byte(0xFF)
		if curve == ecdh.P521() {
			bitMask = byte(0x01)
		}

		var sk *ecdh.PrivateKey
		for {
			if counter > 255 {
				return nil, nil, errors.New("unable to derive keypair from seed")
			}

			bytes, err := kem.labeledExpand(dkpPrk, []byte("candidate"), []byte{uint8(counter)}, kem.nSk)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to expand seed prk: %w", err)
			}
			bytes[0] &= bitMask

			sk, err = kem.DeserializePrivateKey(bytes)
			if err == nil {
				break
			}

			counter++
		}

		return sk.PublicKey(), sk, nil
	}
}

func xDeriver(kem *dhkem, seed []byte) (*ecdh.PublicKey, *ecdh.PrivateKey, error) {
	if len(seed) != int(kem.nSk) {
		return nil, nil, errors.New("invalid seed size")
	}

	dkpPrk := kem.labeledExtract([]byte(""), []byte("dkp_prk"), seed)
	skRaw, err := kem.labeledExpand(dkpPrk, []byte("sk"), []byte(""), kem.nSk)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate secret key seed: %w", err)
	}

	sk, err := ecdh.X25519().NewPrivateKey(skRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid secret key: %w", err)
	}

	return sk.PublicKey(), sk, nil
}
