package vault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"

	"github.com/DataDog/go-secure-sdk/kms"
	"github.com/DataDog/go-secure-sdk/kms/vault/logical"
)

type service struct {
	logical   logical.Logical
	mountPath string
	keyName   string

	keyType              kms.KeyType
	publicKeys           map[int]crypto.PublicKey
	lastVersion          int
	minDecryptionVersion int
	canSign              bool
	canEncrypt           bool
	canDecrypt           bool
	canExport            bool
	autoRotationPeriod   time.Duration

	mu sync.RWMutex
}

// New instantiates a Vault transit backend encryption service.
func New(ctx context.Context, client *api.Client, mountPath, keyName string) (kms.Service, error) {
	// Check arguments
	if client == nil {
		return nil, errors.New("client must not be nil")
	}
	if mountPath == "" {
		mountPath = "transit"
	}
	if keyName == "" {
		return nil, errors.New("key name must not be blank")
	}

	// Create the service instance
	s := &service{
		logical:     client.Logical(),
		mountPath:   strings.TrimSuffix(path.Clean(mountPath), "/"),
		keyName:     keyName,
		lastVersion: 1,
		publicKeys:  map[int]crypto.PublicKey{},
	}

	// Resolve remote key features
	if err := s.resolveKeyCapabilities(ctx); err != nil {
		return nil, fmt.Errorf("error occurred during key feature resolution: %w", err)
	}

	return s, nil
}

// -----------------------------------------------------------------------------

func (s *service) Encrypt(ctx context.Context, cleartext []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check arguments
	if !s.canEncrypt {
		return nil, errors.New("encrypt operation is not supported by the key")
	}
	if s.lastVersion == 0 {
		return nil, errors.New("key has an invalid version")
	}
	if cleartext == nil {
		return nil, fmt.Errorf("cleartext could not be nil")
	}

	// Prepare query
	encryptPath := sanitizePath(path.Join(url.PathEscape(s.mountPath), "encrypt", url.PathEscape(s.keyName)))
	data := map[string]interface{}{
		"plaintext":   base64.StdEncoding.EncodeToString(cleartext),
		"key_version": s.lastVersion,
	}

	// Send to Vault.
	secret, err := s.logical.WriteWithContext(ctx, encryptPath, data)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt with '%s:v%d' key: %w", s.keyName, s.lastVersion, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("unable to encrypt with '%s:v%d' key: nil response", s.keyName, s.lastVersion)
	}

	// Parse server response.
	if cipherText, ok := secret.Data["ciphertext"].(string); ok && cipherText != "" {
		// Remove prefix
		cipherText = strings.TrimPrefix(cipherText, fmt.Sprintf("vault:v%d:", s.lastVersion))
		return []byte(cipherText), nil
	}

	// Return error.
	return nil, errors.New("could not encrypt given data")
}

func (s *service) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check arguments
	if !s.canDecrypt {
		return nil, errors.New("decrypt operation is not supported by the key")
	}
	if s.lastVersion == 0 {
		return nil, errors.New("key has an invalid version")
	}
	if ciphertext == nil {
		return nil, fmt.Errorf("ciphertext could not be nil")
	}

	// Prepare query
	decryptPath := sanitizePath(path.Join(url.PathEscape(s.mountPath), "decrypt", url.PathEscape(s.keyName)))
	data := map[string]interface{}{
		"ciphertext": fmt.Sprintf("vault:v%d:%s", s.lastVersion, string(ciphertext)),
	}

	// Send to Vault.
	secret, err := s.logical.WriteWithContext(ctx, decryptPath, data)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt with '%s:v%d' key: %w", s.keyName, s.lastVersion, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("unable to decrypt with '%s:v%d' key: nil response", s.keyName, s.lastVersion)
	}

	// Parse server response.
	if plainText64, ok := secret.Data["plaintext"].(string); ok && plainText64 != "" {
		plainText, err := base64.StdEncoding.DecodeString(plainText64)
		if err != nil {
			return nil, fmt.Errorf("unable to decode secret: %w", err)
		}

		// Return no error
		return plainText, nil
	}

	// Return error.
	return nil, errors.New("could not decrypt given data")
}

func (s *service) Sign(ctx context.Context, protected []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check arguments
	if !s.canSign {
		return nil, errors.New("sign operation is not supported by the key")
	}
	if s.lastVersion == 0 {
		return nil, errors.New("key has an invalid version")
	}
	if protected == nil {
		return nil, fmt.Errorf("protected could not be nil")
	}

	// Prepare query
	signPath := sanitizePath(path.Join(url.PathEscape(s.mountPath), "sign", url.PathEscape(s.keyName)))
	data := map[string]interface{}{
		"input":                base64.StdEncoding.EncodeToString(protected),
		"marshaling_algorithm": "jws",
		"key_version":          s.lastVersion,
	}

	// Send to Vault.
	secret, err := s.logical.WriteWithContext(ctx, signPath, data)
	if err != nil {
		return nil, fmt.Errorf("unable to sign with '%s:v%d' key: %w", s.keyName, s.lastVersion, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("unable to sign with '%s:v%d' key: nil response", s.keyName, s.lastVersion)
	}

	// Parse server response.
	if signature, ok := secret.Data["signature"].(string); ok && signature != "" {
		// Remove prefix
		signature = strings.TrimPrefix(signature, fmt.Sprintf("vault:v%d:", s.lastVersion))
		return []byte(signature), nil
	}

	// Return error.
	return nil, errors.New("could not sign given data")
}

func (s *service) Verify(ctx context.Context, protected, signature []byte) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check arguments
	if !s.canSign {
		return errors.New("verify operation is not supported by the key")
	}
	if s.lastVersion == 0 {
		return errors.New("key has an invalid version")
	}
	if protected == nil {
		return fmt.Errorf("protected could not be nil")
	}
	if signature == nil {
		return fmt.Errorf("signature could not be nil")
	}

	// Encode data
	encodedInput := base64.StdEncoding.EncodeToString(protected)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// Prepare batch requests
	batchInputs := []any{}
	for i := s.minDecryptionVersion; i <= s.lastVersion; i++ {
		batchInputs = append(batchInputs, map[string]any{
			"key_version":          i,
			"marshaling_algorithm": "jws",
			"signature":            encodedSignature,
			"input":                encodedInput,
		})
	}

	// Prepare query
	signPath := sanitizePath(path.Join(url.PathEscape(s.mountPath), "verify", url.PathEscape(s.keyName)))
	data := map[string]interface{}{
		"batch_inputs": batchInputs,
	}

	// Send to Vault.
	response, err := s.logical.WriteWithContext(ctx, signPath, data)
	if err != nil {
		return fmt.Errorf("unable to verify with '%s:v%d' key: %w", s.keyName, s.lastVersion, err)
	}
	if response == nil {
		return fmt.Errorf("unable to verify with '%s:v%d' key: nil response", s.keyName, s.lastVersion)
	}

	// Parse server response.
	batchResults := struct {
		Results []struct {
			Valid bool `mapstructure:"valid"`
		} `mapstructure:"batch_results"`
	}{}
	if errPki := mapstructure.WeakDecode(response.Data, &batchResults); errPki != nil {
		return fmt.Errorf("unable to decode batch results structure: %w", errPki)
	}

	// Check if we have at least one valid response
	for i := range batchResults.Results {
		if batchResults.Results[i].Valid {
			return nil
		}
	}

	// Return error.
	return errors.New("could not verify the given signature")
}

func (s *service) PublicKey(_ context.Context) (crypto.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch s.keyType {
	case kms.KeyTypeSymmetric, kms.KeyTypeHMAC:
		return nil, errors.New("the key doesn't have a public keys")
	default:
	}

	return s.publicKeys[s.lastVersion], nil
}

func (s *service) VerificationPublicKeys(_ context.Context) ([]crypto.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch s.keyType {
	case kms.KeyTypeSymmetric, kms.KeyTypeHMAC:
		return nil, errors.New("the key doesn't have a public keys")
	default:
	}

	var result []crypto.PublicKey
	for v, k := range s.publicKeys {
		if v >= s.minDecryptionVersion {
			result = append(result, k)
		}
	}

	return result, nil
}

func (s *service) RotateKey(ctx context.Context) error {
	// Prepare query
	rotatePath := sanitizePath(path.Join(url.PathEscape(s.mountPath), "keys", url.PathEscape(s.keyName), "rotate"))

	// Send to Vault.
	response, err := s.logical.WriteWithContext(ctx, rotatePath, nil)
	if err != nil {
		return fmt.Errorf("unable to rotate '%s:v%d' key: %w", s.keyName, s.lastVersion, err)
	}
	if response == nil {
		return fmt.Errorf("unable to rotate '%s:v%d' key: nil response", s.keyName, s.lastVersion)
	}

	// Refresh key information.
	return s.resolveKeyCapabilities(ctx)
}

func (s *service) ExportKey(ctx context.Context) (kms.KeyType, string, error) {
	// Check arguments
	if !s.canExport {
		return kms.KeyTypeUnknown, "", errors.New("export operation is not supported by the key")
	}

	// Retrieve the Vault key type.
	keyTypePath := ""
	switch s.keyType {
	case kms.KeyTypeECDSA, kms.KeyTypeRSA, kms.KeyTypeEd25519:
		keyTypePath = "signing-key"
	case kms.KeyTypeHMAC:
		keyTypePath = "hmac-key"
	case kms.KeyTypeSymmetric:
		keyTypePath = "encryption-key"
	default:
		return kms.KeyTypeUnknown, "", errors.New("key type is not mapped to vault")
	}

	// Prepare query
	rotatePath := sanitizePath(path.Join(url.PathEscape(s.mountPath), "export", keyTypePath, url.PathEscape(s.keyName), fmt.Sprintf("/%d", s.lastVersion)))

	// Send to Vault.
	response, err := s.logical.ReadWithContext(ctx, rotatePath)
	if err != nil {
		return kms.KeyTypeUnknown, "", fmt.Errorf("unable to export '%s:v%d' key: %w", s.keyName, s.lastVersion, err)
	}
	if response == nil {
		return kms.KeyTypeUnknown, "", fmt.Errorf("unable to export '%s:v%d' key: nil response", s.keyName, s.lastVersion)
	}

	// Decode response information
	keyExport := struct {
		Name string            `mapstructure:"name"`
		Keys map[string]string `mapstructure:"keys"`
	}{}
	if errKi := mapstructure.WeakDecode(response.Data, &keyExport); errKi != nil {
		return kms.KeyTypeUnknown, "", fmt.Errorf("unable to decode %q key export response: %w", s.keyName, errKi)
	}

	// Ensure correct response.
	switch {
	case keyExport.Name != s.keyName:
		return kms.KeyTypeUnknown, "", fmt.Errorf("invalid response from Vault, got a different key related response (expected %q, got %q)", s.keyName, keyExport.Name)
	case len(keyExport.Keys) == 0:
		return kms.KeyTypeUnknown, "", fmt.Errorf("invalid response from Vault, got a empty key for %q", s.keyName)
	case len(keyExport.Keys) > 1:
		return kms.KeyTypeUnknown, "", fmt.Errorf("invalid response from Vault, got a more keys than expected for %q", s.keyName)
	}

	return s.keyType, keyExport.Keys[fmt.Sprintf("%d", s.lastVersion)], nil
}

// -----------------------------------------------------------------------------

func (s *service) resolveKeyCapabilities(ctx context.Context) error {
	// Prepare query
	keyPath := sanitizePath(path.Join(url.PathEscape(s.mountPath), "keys", url.PathEscape(s.keyName)))

	// Send to Vault.
	response, err := s.logical.ReadWithContext(ctx, keyPath)
	if err != nil {
		return fmt.Errorf("unable to retrieve key information with %q key: %w", s.keyName, err)
	}
	if response == nil {
		return fmt.Errorf("unable to retrieve key information with %q key: nil response", s.keyName)
	}

	return s.decodeKeyInformation(response)
}

func (s *service) decodeKeyInformation(response *api.Secret) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Decode key information
	keyInfo := struct {
		KeyType              string      `mapstructure:"type"`
		Keys                 interface{} `mapstructure:"keys"`
		LatestVersion        int         `mapstructure:"latest_version"`
		MinDecryptionVersion int         `mapstructure:"min_decryption_version"`
		MinEncryptionVersion int         `mapstructure:"min_encryption_version"`
		SupportsSigning      bool        `mapstructure:"supports_signing"`
		SupportsEncryption   bool        `mapstructure:"supports_encryption"`
		SupportsDecryption   bool        `mapstructure:"supports_decryption"`
		Exportable           bool        `mapstructure:"exportable"`
		AutoRotatePeriod     uint64      `mapstructure:"auto_rotate_period"`
	}{}
	if errKi := mapstructure.WeakDecode(response.Data, &keyInfo); errKi != nil {
		return fmt.Errorf("unable to decode '%s' key information: %w", s.keyName, errKi)
	}

	// Add local keytype
	switch keyInfo.KeyType {
	case "aes128-gcm96", "aes256-gcm96", "chacha20-poly1305":
		s.keyType = kms.KeyTypeSymmetric
	case "hmac":
		s.keyType = kms.KeyTypeHMAC
	case "rsa-2048", "rsa-3072", "rsa-4096":
		s.keyType = kms.KeyTypeRSA
	case "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		s.keyType = kms.KeyTypeECDSA
	case "ed25519":
		s.keyType = kms.KeyTypeEd25519
	default:
		return errors.New("unsupported key type")
	}

	// Preload the public key for asymmetric keys.
	if s.keyType != kms.KeyTypeSymmetric && s.keyType != kms.KeyTypeHMAC {
		// Extract public key
		publicKeyInfo := map[int]struct {
			PublicKey string `mapstructure:"public_key"`
		}{}
		if errPki := mapstructure.WeakDecode(keyInfo.Keys, &publicKeyInfo); errPki != nil {
			return fmt.Errorf("unable to decode public key structure: %w", errPki)
		}

		for version := range publicKeyInfo {
			// Skip if not supported
			if version < keyInfo.MinDecryptionVersion {
				continue
			}

			// Decode public key
			pub, err := s.createPublicKey(publicKeyInfo[version].PublicKey)
			if err != nil {
				return fmt.Errorf("unable to decode public key version %d: %w", version, err)
			}

			// Assign known public key to service
			s.publicKeys[version] = pub
		}

		// Sanity check
		if len(s.publicKeys) == 0 {
			return fmt.Errorf("no applicable public key identified")
		}
	}

	// Assign features to service
	s.lastVersion = keyInfo.LatestVersion
	s.minDecryptionVersion = keyInfo.MinDecryptionVersion
	s.canDecrypt = keyInfo.SupportsDecryption
	s.canEncrypt = keyInfo.SupportsEncryption
	s.canSign = keyInfo.SupportsSigning
	s.canExport = keyInfo.Exportable
	s.autoRotationPeriod = time.Duration(keyInfo.AutoRotatePeriod) * time.Second

	return nil
}

func (s *service) createPublicKey(keyData string) (crypto.PublicKey, error) {
	switch s.keyType {
	case kms.KeyTypeRSA:
		block, _ := pem.Decode([]byte(keyData))
		if block == nil {
			return nil, errors.New("unable to decode RSA public key")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse RSA public key: %w", err)
		}
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("unable to cast to RSA public key")
		}
		return key, nil
	case kms.KeyTypeECDSA:
		block, _ := pem.Decode([]byte(keyData))
		if block == nil {
			return nil, errors.New("unable to decode ECDSA public key")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse ECDSA public key: %w", err)
		}
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("unable to cast to ECDSA public key")
		}
		return key, nil
	case kms.KeyTypeEd25519:
		key, err := base64.StdEncoding.DecodeString(keyData)
		if err != nil {
			return nil, fmt.Errorf("unable to parse Ed25519 public key: %w", err)
		}
		return ed25519.PublicKey(key), nil
	}
	return nil, errors.New("unknown public key type")
}
