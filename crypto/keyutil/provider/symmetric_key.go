package provider

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/awnumar/memguard"

	"github.com/DataDog/go-secure-sdk/crypto/encryption"
	"github.com/DataDog/go-secure-sdk/crypto/keyutil"

	"golang.org/x/crypto/hkdf"
)

var _ SymmetricKey = (*defaultSymmetricKey)(nil)

type defaultSymmetricKey struct {
	alias    KeyAlias
	key      *memguard.Enclave
	purposes KeyPurposes
}

func (sk *defaultSymmetricKey) Can(purpose KeyPurpose) bool {
	return sk.purposes.Can(purpose)
}

func (sk *defaultSymmetricKey) Alias() KeyAlias {
	return sk.alias
}

// AsBytes exports the symmetric secret as byte array.
// The key must be imported with the ExportableKey flag enabled.
func (sk *defaultSymmetricKey) AsBytes() ([]byte, error) {
	if !sk.Can(ExportableKey) {
		return nil, errors.New("this key is not exportable")
	}

	// Open enclave
	lb, err := sk.key.Open()
	if err != nil {
		return nil, fmt.Errorf("unable to open key enclave: %w", err)
	}
	defer lb.Destroy()

	// Copy the key to prevent dereferencement
	raw := make([]byte, lb.Size())
	copy(raw, lb.Bytes())

	return raw, nil
}

// AsCabin exports the symmetric secret as a secret cabin.
// The key must be imported with the ExportableKey flag enabled.
func (sk *defaultSymmetricKey) AsCabin(password []byte) ([]byte, error) {
	if !sk.Can(ExportableKey) {
		return nil, errors.New("this key is not exportable")
	}

	// Open enclave
	lb, err := sk.key.Open()
	if err != nil {
		return nil, fmt.Errorf("unable to open key enclave: %w", err)
	}
	defer lb.Destroy()

	var out bytes.Buffer
	if err := encryption.SealSecretCabin(&out, lb, password); err != nil {
		return nil, fmt.Errorf("unable to export symmetric key as a secret cabin: %w", err)
	}

	return out.Bytes(), nil
}

func (sk *defaultSymmetricKey) ValueEncryption() (encryption.ValueAEAD, error) {
	if !sk.Can(EncryptionPurpose) || sk.Can(SignaturePurpose) {
		return nil, errors.New("this key is not useable for encryption")
	}

	// Open enclave
	lb, err := sk.key.Open()
	if err != nil {
		return nil, fmt.Errorf("unable to open key enclave: %w", err)
	}
	defer lb.Destroy()

	//nolint:wrapcheck
	return encryption.Value(lb.Bytes())
}

func (sk *defaultSymmetricKey) ChunkedEncryption() (encryption.ChunkedAEAD, error) {
	if !sk.Can(EncryptionPurpose) || sk.Can(SignaturePurpose) {
		return nil, errors.New("this key is not useable for encryption")
	}

	// Open enclave
	lb, err := sk.key.Open()
	if err != nil {
		return nil, fmt.Errorf("unable to open key enclave: %w", err)
	}
	defer lb.Destroy()

	//nolint:wrapcheck
	return encryption.Chunked(lb.Bytes())
}

func (sk *defaultSymmetricKey) ConvergentEncryption() (encryption.ValueAEAD, error) {
	if !sk.Can(EncryptionPurpose) || sk.Can(SignaturePurpose) {
		return nil, errors.New("this key is not useable for encryption")
	}

	// Open enclave
	lb, err := sk.key.Open()
	if err != nil {
		return nil, fmt.Errorf("unable to open key enclave: %w", err)
	}
	defer lb.Destroy()

	//nolint:wrapcheck
	return encryption.Convergent(lb.Bytes())
}

func (sk *defaultSymmetricKey) HMAC(h func() hash.Hash) (hash.Hash, error) {
	if !sk.Can(SignaturePurpose) {
		return nil, errors.New("this key is not useable for signature")
	}

	// Open enclave
	lb, err := sk.key.Open()
	if err != nil {
		return nil, fmt.Errorf("unable to open key enclave: %w", err)
	}
	defer lb.Destroy()

	return hmac.New(h, lb.Bytes()), nil
}

func (sk *defaultSymmetricKey) NewCipher() (cipher.Block, error) {
	if !sk.Can(EncryptionPurpose) {
		return nil, errors.New("this key is not useable for encryption")
	}

	// Open enclave
	lb, err := sk.key.Open()
	if err != nil {
		return nil, fmt.Errorf("unable to open key enclave: %w", err)
	}
	defer lb.Destroy()

	//nolint:wrapcheck
	return aes.NewCipher(lb.Bytes())
}

func (sk *defaultSymmetricKey) DeriveSymmetric(salt, info []byte, dkLen uint32, purposes ...KeyPurpose) (SymmetricKey, error) {
	if !sk.Can(KeyDerivationPurpose) {
		return nil, errors.New("this key is not useable for derivation")
	}
	if info == nil {
		return nil, errors.New("derivation information must not be nil")
	}
	if dkLen < minSecretLength || dkLen > maxSecretLength {
		return nil, fmt.Errorf("symmetric key length must be greater than %d and lower than %d", minSecretLength, maxSecretLength)
	}

	// Assign purposes
	var kp KeyPurposes
	for _, p := range purposes {
		kp = kp.Set(p)
	}

	// Open enclave
	lb, err := sk.key.Open()
	if err != nil {
		return nil, fmt.Errorf("unable to open key enclave: %w", err)
	}
	defer lb.Destroy()

	// Generate a new key alias
	keyAlias, err := newKeyAlias()
	if err != nil {
		return nil, fmt.Errorf("unable to generate a new key alias: %w", err)
	}

	// Initialize deriver
	out := make([]byte, dkLen)
	dk := hkdf.New(sha256.New, lb.Bytes(), salt, info)
	if _, err := io.ReadFull(dk, out); err != nil {
		return nil, fmt.Errorf("unable to derive sub symmetric key: %w", err)
	}
	defer memguard.WipeBytes(out)

	return &defaultSymmetricKey{
		alias:    keyAlias,
		key:      memguard.NewEnclave(out),
		purposes: kp,
	}, nil
}

func (sk *defaultSymmetricKey) DeriveAsymmetric(salt, info []byte, kty keyutil.KeyType, purposes ...KeyPurpose) (PublicKey, PrivateKey, error) {
	if !sk.Can(KeyDerivationPurpose) {
		return nil, nil, errors.New("this key is not useable for derivation")
	}

	// Assign purposes
	var kp KeyPurposes
	for _, p := range purposes {
		kp = kp.Set(p)
	}

	// Open enclave
	lb, err := sk.key.Open()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to open key enclave: %w", err)
	}
	defer lb.Destroy()

	// Generate a new key alias
	keyAlias, err := newKeyAlias()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate a new key alias: %w", err)
	}

	// Generate key pair from the seed
	pub, priv, err := keyutil.GenerateKeyPairWithRand(hkdf.New(sha256.New, lb.Bytes(), salt, info), kty)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate keypair from the seed: %w", err)
	}

	return &defaultPublicKey{
			alias:    keyAlias,
			key:      pub,
			purposes: kp,
		},
		&defaultPrivateKey{
			alias:    keyAlias,
			key:      priv.(crypto.Signer),
			purposes: kp,
		}, nil
}
