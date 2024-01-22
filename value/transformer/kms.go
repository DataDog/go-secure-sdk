package transformer

import (
	"context"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/DataDog/go-secure-sdk/crypto/encryption"
	"github.com/DataDog/go-secure-sdk/generator/randomness"
	"github.com/DataDog/go-secure-sdk/kms"
)

// RemoteKMSEncryption aggregates required interface for the transformer.
type RemoteKMSEncryption interface {
	kms.Decryptor
	kms.Encryptor
}

// KMS initializes an KMS-based encryption value transformer. To prevent data
// moves, the data is locally encrypted with a randomly generated encryption key
// called the data encryption key (DEK). This key is encrypted by the remote KMS
// to protect the DEK.
//
// Be aware of the transactional cost applied to the usage of this transformer.
// Each operation calls the remote KMS service, the overall performance is
// strictly bound to the remote KMS service performance and its reachability
// cost.
//
// This transformer is not recommended to be used with atomic structure fields,
// please consider wrapping a complex object to reduce transformer calls.
// By using this transformer in an inappropriate way, you could be responsible
// for a KMS outage.
func KMS(srv RemoteKMSEncryption) Transformer {
	return &kmsTransformer{
		srv: srv,
	}
}

// -----------------------------------------------------------------------------
type kmsTransformer struct {
	srv RemoteKMSEncryption
}

type kmsenvelope struct {
	_ struct{} `cbor:",toarray"`

	DEK     []byte `cbor:"1,keyasint"`
	Payload []byte `cbor:"2,keyasint"`
}

func (t *kmsTransformer) Encode(plaintext []byte) ([]byte, error) {
	// Generate random key
	dek, err := randomness.Bytes(32)
	if err != nil {
		return nil, fmt.Errorf("unable to generate data encryption key")
	}

	// Encrypt the data encryption key
	encryptedKey, err := t.srv.Encrypt(context.Background(), dek)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt data encryption key: %w", err)
	}

	// Initialize AEAD Value encryption
	aead, err := encryption.Value(dek)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize data encryption: %w", err)
	}

	// Encrypt the input data locally
	ciphertext, err := aead.Seal(plaintext)
	if err != nil {
		return nil, fmt.Errorf("unable to apply value transformation: %w", err)
	}

	// Encode as CBOR
	envelope, err := cbor.Marshal(&kmsenvelope{
		DEK:     encryptedKey,
		Payload: ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to serialize envelope: %w", err)
	}

	return envelope, nil
}

func (t *kmsTransformer) Decode(raw []byte) ([]byte, error) {
	// Decode envelope
	var envelope kmsenvelope
	if err := cbor.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("unable to decode envelope: %w", err)
	}

	// Decrypt the DEK
	dek, err := t.srv.Decrypt(context.Background(), envelope.DEK)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt data encryption key: %w", err)
	}

	// Initialize AEAD Value encryption
	aead, err := encryption.Value(dek)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize data encryption: %w", err)
	}

	// Decrypt the payload
	plaintext, err := aead.Open(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("unable to revert value transformation: %w", err)
	}

	return plaintext, nil
}
