package signature

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

func ExampleECDSASigner() {
	// Generate an EC keypair
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Wrap the key with an ECDSA signer instance
	signer, err := ECDSASigner(pk)
	if err != nil {
		panic(err)
	}

	msg := []byte("Hello World !")

	// Sign the message
	sig, err := signer.Sign(msg)
	if err != nil {
		panic(err)
	}

	// Create the verifier with the matching public key
	verifier, err := ECDSAVerifier(&pk.PublicKey)
	if err != nil {
		panic(err)
	}

	// Verify the message signature.
	if err := verifier.Verify(msg, sig); err != nil {
		panic(err)
	}
}

func ExampleEd25519Signer() {
	// Generate an Ed25519 keypair
	pub, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Wrap the key with an Ed25519 signer instance
	signer, err := Ed25519Signer(pk)
	if err != nil {
		panic(err)
	}

	msg := []byte("Hello World !")

	// Sign the message
	sig, err := signer.Sign(msg)
	if err != nil {
		panic(err)
	}

	// Create the verifier with the matching public key
	verifier, err := Ed25519Verifier(pub)
	if err != nil {
		panic(err)
	}

	// Verify the message signature.
	if err := verifier.Verify(msg, sig); err != nil {
		if errors.Is(err, ErrInvalidSignature) {
			// Invalid signature
		}
		panic(err)
	}
}

func ExampleFromPublicKey() {
	msg := []byte("...")
	sig := []byte("...")

	// Generate an Ed25519 keypair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Use FromPublicKey to detect the public key type and instantiate the
	// appropriate verifier.
	v, err := FromPublicKey(pub)
	if err != nil {
		panic(err)
	}

	// Use the verifier
	if err := v.Verify(msg, sig); err != nil {
		if errors.Is(err, ErrInvalidSignature) {
			// Invalid signature
		}
		// Other error
	}
}

func ExampleFromPrivateKey() {
	msg := []byte("...")

	// Generate an Ed25519 keypair
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Use FromPrivateKey to detect the private key type and instantiate the
	// appropriate signer.
	s, err := FromPrivateKey(priv)
	if err != nil {
		panic(err)
	}

	// Use the signer
	sig, err := s.Sign(msg)
	if err != nil {
		panic(err)
	}

	fmt.Println(hex.Dump(append(sig, msg...)))
}

func ExampleFromPrivateKeyPEM() {
	msg := []byte("...")
	pem := `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCwS7FZqyX0Xbk1hvCp\ngCuVKJL/NjF0B8QCpzWbGCXmPA==
-----END PRIVATE KEY-----`

	// Use PrivateKeyFromPEM to decode and detect the private key type and
	// instantiate the appropriate signer.
	s, err := FromPrivateKeyPEM(strings.NewReader(pem))
	if err != nil {
		panic(err)
	}

	// Use the signer
	sig, err := s.Sign(msg)
	if err != nil {
		panic(err)
	}

	fmt.Println(hex.Dump(append(sig, msg...)))
}

func ExampleFromPublicKeyPEM() {
	msg := []byte("...")
	sig := []byte("...")
	pem := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh4GrAmD45m+8x7VF4W3DjSBxIRVu
zEtcyFbY0FtEDPoZ974Ayk8tWjytNkolc5oCNwHhfQ6QJ4brchPbOgqFOg==
-----END PUBLIC KEY-----`

	// Use FromPublicKeyPEM to decode and detect the public key type and
	// instantiate the appropriate verifier.
	v, err := FromPublicKeyPEM(strings.NewReader(pem))
	if err != nil {
		panic(err)
	}

	// Use the verifier
	if err := v.Verify(msg, sig); err != nil {
		if errors.Is(err, ErrInvalidSignature) {
			// Invalid signature
		}
		// Other error
	}
}
