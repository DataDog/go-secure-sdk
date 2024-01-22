package encryption

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/awnumar/memguard"

	"github.com/DataDog/go-secure-sdk/generator/randomness"

	"golang.org/x/crypto/scrypt"
)

// Inspired from github.com/theupdateframework/go-tuf/encrypted

const (
	cabinDefaultKDFName         = "scrypt"
	cabinDefaultKDFParamVersion = 1
	defaultScryptSaltLength     = 16
	minPasswordLength           = 16
)

type cabinEnvelope struct {
	KDF        cabinKDF    `json:"kdf"`
	Cipher     cabinCipher `json:"cipher"`
	Ciphertext []byte      `json:"ciphertext"`
}

type cabinKDF struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Salt    []byte `json:"salt"`
}

type cabinCipher struct {
	Name string `json:"name"`
}

type cabinKDFParams struct {
	N int `json:"N"`
	R int `json:"r"`
	P int `json:"p"`
}

// Don't embed the KDF settings in the encoded secret to ensure tamper-proof
// settings and progressive enhancements.
var kdfStrategies = map[string]map[int]cabinKDFParams{
	"scrypt": {
		1: cabinKDFParams{
			N: 131072, // 2^17 - OWASP Recommendation
			R: 8,
			P: 1,
		},
	},
}

// ParseSecretCabin returns the secret value encoded using dog-cabin envelope.
// If an incorrect password is detected an x509.IncorrectPasswordError is
// returned.
//
// Datadog cabin keys are encrypted under a password using scrypt as a KDF and
// use the appropriate encryption based on the environment settings.
func ParseSecretCabin(data, password []byte) (*memguard.LockedBuffer, error) {
	// Check arguments
	if len(password) < minPasswordLength {
		return nil, errors.New("password must have at least 16bytes or 128bits")
	}

	var env cabinEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("error unmarshaling key: %w", err)
	}

	// Ensure supported KDF
	versions, ok := kdfStrategies[env.KDF.Name]
	if !ok {
		return nil, fmt.Errorf("unsupported KDF operation %q", env.KDF.Name)
	}

	// Ensure supported KDF version
	params, ok := versions[env.KDF.Version]
	if !ok {
		return nil, fmt.Errorf("unsupported KDF parameter version %d", env.KDF.Version)
	}

	// Ensure compatible parameters to prevent DoS via tampered KDF settings.
	if len(env.KDF.Salt) != defaultScryptSaltLength {
		return nil, fmt.Errorf("invalid kdf salt")
	}

	// Derive secretbox key
	k, err := scrypt.Key(password, env.KDF.Salt, params.N, params.R, params.P, 32)
	if err != nil {
		return nil, fmt.Errorf("error generating key: %w", err)
	}

	// Try to open the secret cabin
	out, err := Open([][]byte{k}, env.Ciphertext, []byte("datadog-secret-cabin-v1"))
	if err != nil {
		return nil, fmt.Errorf("unable to unseal secret cabin: %w", err)
	}

	// Return raw content
	return memguard.NewBufferFromBytes(out), nil
}

// SealSecretCabin seals the input data with the given password and wrties the
// envelope to the writer.
func SealSecretCabin(w io.Writer, secret *memguard.LockedBuffer, password []byte) error {
	// Check arguments
	if secret == nil {
		return errors.New("secret must not be nil")
	}
	if len(password) < minPasswordLength {
		return errors.New("password must have at least 16bytes or 128bits")
	}

	// Generate a random salt
	salt, err := randomness.Bytes(defaultScryptSaltLength)
	if err != nil {
		return fmt.Errorf("unable to generate random salt: %w", err)
	}

	// Ensure supported KDF
	versions, ok := kdfStrategies[cabinDefaultKDFName]
	if !ok {
		return fmt.Errorf("unsupported KDF operation %q", cabinDefaultKDFName)
	}

	// Ensure supported KDF version
	params, ok := versions[cabinDefaultKDFParamVersion]
	if !ok {
		return fmt.Errorf("unsupported KDF parameter version %d", cabinDefaultKDFParamVersion)
	}

	// Create the envelope
	env := cabinEnvelope{
		KDF: cabinKDF{
			Name:    cabinDefaultKDFName,
			Salt:    salt,
			Version: cabinDefaultKDFParamVersion,
		},
	}

	// Derive encryption key
	k, err := scrypt.Key(password, env.KDF.Salt, params.N, params.R, params.P, 32)
	if err != nil {
		return fmt.Errorf("error generating key: %w", err)
	}

	// Initialize value encryption
	aead, err := Value(k)
	if err != nil {
		return fmt.Errorf("unable to initialize value encryption: %w", err)
	}

	// Assign cipher id
	env.Cipher.Name = fmt.Sprintf("datadog/%x", aead.CipherID())

	// Seal sensitive data
	out, err := aead.SealWithContext(secret.Bytes(), []byte("datadog-secret-cabin-v1"))
	if err != nil {
		return fmt.Errorf("unable to encrypt data: %w", err)
	}

	// Assign to envelope
	env.Ciphertext = out

	// Marshall envelope
	if err := json.NewEncoder(w).Encode(&env); err != nil {
		return fmt.Errorf("unable to encode envelope as JSON: %w", err)
	}

	// Return raw content
	return nil
}
