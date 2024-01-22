package provider

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/awnumar/memguard"

	"github.com/DataDog/go-secure-sdk/crypto/keyutil"
	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

const (
	minSecretLength = 16
	maxSecretLength = 1024
)

type defaultProvider struct {
	symmetricKeys sync.Map
	publicKeys    sync.Map
	privateKeys   sync.Map
}

// New mutable empty key provider
func New() MutableKeyProvider {
	return &defaultProvider{}
}

// Build an immutable key provider.
func Build(opts ...Option) (KeyProvider, error) {
	kp := &defaultProvider{}

	// Apply builder options
	for _, o := range opts {
		if err := o(kp); err != nil {
			return nil, fmt.Errorf("unable to build the key provider: %w", err)
		}
	}

	return kp, nil
}

// -----------------------------------------------------------------------------

var _ KeyResolver = (*defaultProvider)(nil)

// GetSymmetricFor resolves the key alias expecting a symmetric key matching the given purpose.
func (p *defaultProvider) GetSymmetricFor(alias KeyAlias, purpose KeyPurpose) (SymmetricKey, error) {
	// Resolve from internal map
	k, ok := p.symmetricKeys.Load(p.keyReducer(alias))
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Ensure matching type
	sk, ok := k.(SymmetricKey)
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Ensure purpose
	if !sk.Can(purpose) {
		return nil, ErrKeyNotFound
	}

	// Ensure right key alias
	if sk.Alias() != alias {
		return nil, ErrKeyNotFound
	}

	return sk, nil
}

// GetPrivateFor resolves the key alias expecting a private key matching the gievn purpose.
func (p *defaultProvider) GetPrivateFor(alias KeyAlias, purpose KeyPurpose) (PrivateKey, error) {
	// Resolve from internal map
	k, ok := p.privateKeys.Load(p.keyReducer(alias))
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Ensure matching type
	pk, ok := k.(PrivateKey)
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Ensure purpose
	if !pk.Can(purpose) {
		return nil, ErrKeyNotFound
	}

	// Ensure right key alias
	if pk.Alias() != alias {
		return nil, ErrKeyNotFound
	}

	return pk, nil
}

// GetPublic resolves the key alias expecting a public key.
func (p *defaultProvider) GetPublic(alias KeyAlias) (PublicKey, error) {
	// Resolve from internal map
	k, ok := p.publicKeys.Load(p.keyReducer(alias))
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Ensure matching type
	pub, ok := k.(PublicKey)
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Ensure right key alias
	if pub.Alias() != alias {
		return nil, ErrKeyNotFound
	}

	return pub, nil
}

// -----------------------------------------------------------------------------

var _ KeyGenerator = (*defaultProvider)(nil)

func (p *defaultProvider) GenerateKeyPair(kty keyutil.KeyType, purposes ...KeyPurpose) (PrivateKey, error) {
	// Assign purposes
	var kp KeyPurposes
	for _, p := range purposes {
		kp = kp.Set(p)
	}

	// Ensure valid purpose set
	if kp.Can(EncryptionPurpose) && kp.Can(SignaturePurpose) {
		return nil, errors.New("encryption and signature purposes are mutually exclusive")
	}

	// Generate a key alias
	keyAlias, err := newKeyAlias()
	if err != nil {
		return nil, fmt.Errorf("unable to generate a key alias: %w", err)
	}

	// Generate the requested key pair
	pub, pk, err := keyutil.GenerateKeyPair(kty)
	if err != nil {
		return nil, fmt.Errorf("unable to generate key pair: %w", err)
	}

	// Compute internal key
	mapKey := p.keyReducer(keyAlias)

	// Store in the internal map
	p.publicKeys.Store(mapKey, &defaultPublicKey{
		alias:    keyAlias,
		key:      pub,
		purposes: kp,
	})

	// Retrieve private key wrapper
	privateKeyWrapper := &defaultPrivateKey{
		alias:    keyAlias,
		key:      pk.(crypto.Signer),
		purposes: kp,
	}
	p.privateKeys.Store(mapKey, privateKeyWrapper)

	return privateKeyWrapper, nil
}

func (p *defaultProvider) GenerateSecret(length int, purposes ...KeyPurpose) (SymmetricKey, error) {
	// Check arguments
	if length < minSecretLength || length > maxSecretLength {
		return nil, fmt.Errorf("symmetric key length must be greater than %d and lower than %d", minSecretLength, maxSecretLength)
	}

	var kp KeyPurposes
	for _, p := range purposes {
		kp = kp.Set(p)
	}

	// Ensure valid purpose set
	if kp.Can(EncryptionPurpose) && kp.Can(SignaturePurpose) {
		return nil, errors.New("encryption and signature purposes are mutually exclusive")
	}

	// Generate a key alias
	keyAlias, err := newKeyAlias()
	if err != nil {
		return nil, fmt.Errorf("unable to generate a key alias: %w", err)
	}

	// Generate random secret value
	value, err := randomness.Bytes(length)
	if err != nil {
		return nil, fmt.Errorf("unable to generate random secret: %w", err)
	}
	defer memguard.WipeBytes(value)

	// Compute internal key
	mapKey := p.keyReducer(keyAlias)
	symKey := &defaultSymmetricKey{
		alias:    keyAlias,
		key:      memguard.NewEnclave(value),
		purposes: kp,
	}

	// Store in the internal map
	p.symmetricKeys.Store(mapKey, symKey)

	return symKey, nil
}

// -----------------------------------------------------------------------------

func (p *defaultProvider) Register(alias KeyAlias, keyFactory KeyFactory) error {
	// Check argument
	if alias == "" {
		return errors.New("key alias must not be blank")
	}
	if keyFactory == nil {
		return errors.New("key factory must not be nil")
	}

	// Get the key
	k, err := keyFactory(alias)
	if err != nil {
		return fmt.Errorf("unable to retrieve a key instance form the factory: %w", err)
	}
	if k == nil {
		return fmt.Errorf("the key factory returned a nil key without error")
	}

	// Compute internal alias
	keyAlias := p.keyReducer(alias)

	// Store the key into the appropriate backend.
	exist := false
	switch tk := k.(type) {
	case PrivateKey:
		_, exist = p.privateKeys.LoadOrStore(keyAlias, tk)
	case PublicKey:
		_, exist = p.publicKeys.LoadOrStore(keyAlias, tk)
	case SymmetricKey:
		_, exist = p.symmetricKeys.LoadOrStore(keyAlias, tk)
	default:
		return errors.New("unable to register unhandled key type")
	}
	if exist {
		return fmt.Errorf("key %q is already registered", alias)
	}

	return nil
}

func (p *defaultProvider) Remove(alias KeyAlias) error {
	// Compute internal key
	keyAlias := p.keyReducer(alias)

	// Try to delete from maps
	if _, present := p.privateKeys.LoadAndDelete(keyAlias); present {
		return nil
	}
	if _, present := p.publicKeys.LoadAndDelete(keyAlias); present {
		return nil
	}
	if _, present := p.symmetricKeys.LoadAndDelete(keyAlias); present {
		return nil
	}

	return ErrKeyNotFound
}

// -----------------------------------------------------------------------------

func (p *defaultProvider) keyReducer(alias KeyAlias) [32]byte {
	// Compress key alias in-memory for stable lookup
	return sha256.Sum256([]byte(alias))
}
