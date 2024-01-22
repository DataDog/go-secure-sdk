package provider

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/awnumar/memguard"
)

// StaticSymmetricSecret creates a key factory based on the given static raw value.
func StaticSymmetricSecret(raw []byte, purposes ...KeyPurpose) KeyFactory {
	return func(alias KeyAlias) (Key, error) {
		// Checck argument
		if alias == "" {
			return nil, errors.New("key alias must not be blank")
		}

		// Assign purposes
		var kp KeyPurposes
		for _, p := range purposes {
			kp = kp.Set(p)
		}

		// Ensure valid purpose set
		if kp.Can(EncryptionPurpose) && kp.Can(SignaturePurpose) {
			return nil, errors.New("encryption and signature purposes are mutually exclusive")
		}

		return &defaultSymmetricKey{
			alias:    alias,
			key:      memguard.NewEnclave(raw),
			purposes: kp,
		}, nil
	}
}

// RandomSymmetricSecret creates a key factory based on the random raw value.
func RandomSymmetricSecret(length int, purposes ...KeyPurpose) KeyFactory {
	return func(alias KeyAlias) (Key, error) {
		// Checck argument
		if alias == "" {
			return nil, errors.New("key alias must not be blank")
		}
		if length < minSecretLength || length > maxSecretLength {
			return nil, fmt.Errorf("symmetric key length must be greater than %d and lower than %d", minSecretLength, maxSecretLength)
		}

		// Assign purposes
		var kp KeyPurposes
		for _, p := range purposes {
			kp = kp.Set(p)
		}

		// Ensure valid purpose set
		if kp.Can(EncryptionPurpose) && kp.Can(SignaturePurpose) {
			return nil, errors.New("encryption and signature purposes are mutually exclusive")
		}

		return &defaultSymmetricKey{
			alias:    alias,
			key:      memguard.NewEnclaveRandom(length),
			purposes: kp,
		}, nil
	}
}

// StaticPublicKey creates a key factory based on the given public key instance.
func StaticPublicKey(key crypto.PublicKey, purposes ...KeyPurpose) KeyFactory {
	return func(alias KeyAlias) (Key, error) {
		// Checck argument
		if alias == "" {
			return nil, errors.New("key alias must not be blank")
		}

		// Assign purposes
		var kp KeyPurposes
		for _, p := range purposes {
			kp = kp.Set(p)
		}

		// Ensure valid purpose set
		if kp.Can(EncryptionPurpose) && kp.Can(SignaturePurpose) {
			return nil, errors.New("encryption and signature purposes are mutually exclusive")
		}

		// Ensure correct type
		switch k := key.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			// Accept
		default:
			return nil, fmt.Errorf("unsupported public key type %T", k)
		}

		return &defaultPublicKey{
			alias:    alias,
			key:      key,
			purposes: kp,
		}, nil
	}
}

// StaticPrivateKey creates a key factory based on the given private key instance.
func StaticPrivateKey(key crypto.Signer, purposes ...KeyPurpose) KeyFactory {
	return func(alias KeyAlias) (Key, error) {
		// Checck argument
		if alias == "" {
			return nil, errors.New("key alias must not be blank")
		}

		// Assign purposes
		var kp KeyPurposes
		for _, p := range purposes {
			kp = kp.Set(p)
		}

		// Ensure valid purpose set
		if kp.Can(EncryptionPurpose) && kp.Can(SignaturePurpose) {
			return nil, errors.New("encryption and signature purposes are mutually exclusive")
		}

		// Ensure correct type
		switch k := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			// Accept
		default:
			return nil, fmt.Errorf("unsupported private key type %T", k)
		}

		return &defaultPrivateKey{
			alias:    alias,
			key:      key,
			purposes: kp,
		}, nil
	}
}
