package encryption

import "io"

// Mode represents encryption mode available.
type Mode uint

const (
	// Keep 0 for automatic detection (TODO)
	// FIPS mode uses FIPS compliant encryption ciphersuites.
	// D1 => HKDF-SHA256_AES256-CTR_HMAC-SHA256
	FIPS Mode = iota + 1
	// Modern uses modern encryption ciphersuites focusing security and performance.
	// D2 => Blake2bXOF_ChaCha20_Keyed-Blake2b
	Modern
)

// maximumKeyLength defines the acceptable key size for encryption implementations.
const maximumKeyLength = 2048

// ValueEncryptor represents finite byte array encryption operations.
type ValueEncryptor interface {
	// Seal the given plaintext.
	Seal(plaintext []byte) ([]byte, error)
	// SealWithContext encrypts the given plaintext and inject all given context
	// information for authentication purpose.
	SealWithContext(plaintext []byte, context ...[]byte) ([]byte, error)
}

// ValueDecryptor represents finite byte array decryption operations.
type ValueDecryptor interface {
	// Open decrypts the given ciphertext.
	Open(ciphertext []byte) ([]byte, error)
	// OpenWithContext decrypts the given ciphertext and inject all given context
	// information for authentication purpose.
	OpenWithContext(ciphertext []byte, context ...[]byte) ([]byte, error)
}

// ValueAEAD represents all encryption/decryption operations for a finite byte array.
type ValueAEAD interface {
	ValueEncryptor
	ValueDecryptor
	CipherID() uint8
}

// ChunkEncryptor represents chunked encryption operations.
type ChunkedEncryptor interface {
	// Seal the given plaintext.
	Seal(dst io.Writer, plaintext io.Reader) error
	// SealWithContext encrypts the given plaintext and inject all given context
	// information for authentication purpose.
	SealWithContext(dst io.Writer, plaintext io.Reader, context ...[]byte) error
}

// ChunkDecryptor represents chunked decryption operations.
type ChunkedDecryptor interface {
	// Open decrypts the given ciphertext.
	Open(dst io.Writer, ciphertext io.Reader) error
	// OpenWithContext decrypts the given ciphertext and inject all given context
	// information for authentication purpose.
	OpenWithContext(dst io.Writer, ciphertext io.Reader, context ...[]byte) error
}

// ChunkedAEAD represents all encryption/decryption operations for input stream.
type ChunkedAEAD interface {
	ChunkedEncryptor
	ChunkedDecryptor
}
