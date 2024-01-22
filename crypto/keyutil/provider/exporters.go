package provider

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"gopkg.in/square/go-jose.v2"

	"github.com/DataDog/go-secure-sdk/crypto/keyutil"
)

func asBytes(key any) ([]byte, error) {
	var (
		raw []byte
		err error
	)

	switch k := key.(type) {
	case ed25519.PublicKey, *ecdsa.PublicKey, *rsa.PublicKey,
		ed25519.PrivateKey, *ecdsa.PrivateKey, *rsa.PrivateKey:
		_, raw, err = keyutil.ToDERBytes(k)
	case []byte:
		raw = k
	default:
		return nil, fmt.Errorf("unknown key type %T", key)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to serialize key as bytes: %w", err)
	}

	return raw, nil
}

func asPEM(key any) (string, error) {
	var (
		raw   []byte
		block string
		err   error
	)

	switch k := key.(type) {
	case ed25519.PublicKey, *ecdsa.PublicKey, *rsa.PublicKey,
		ed25519.PrivateKey, *ecdsa.PrivateKey, *rsa.PrivateKey:
		block, raw, err = keyutil.ToDERBytes(k)
	case []byte:
		block = "SYMMETRIC KEY"
		raw = k
	default:
		return "", fmt.Errorf("unknown key type %T", key)
	}
	if err != nil {
		return "", fmt.Errorf("unable to serialize key as string: %w", err)
	}

	// Prepare PEM block
	out := strings.Builder{}
	if err := pem.Encode(&out, &pem.Block{
		Type:  block,
		Bytes: raw,
	}); err != nil {
		return "", fmt.Errorf("unable to encode the key as PEM block: %w", err)
	}

	return out.String(), nil
}

func asJSON(key *jose.JSONWebKey) (string, error) {
	// Prepare output
	out := strings.Builder{}

	// Encode to JSON
	if err := json.NewEncoder(&out).Encode(key); err != nil {
		return "", fmt.Errorf("unable to encode the key as JSON: %w", err)
	}

	return out.String(), nil
}
