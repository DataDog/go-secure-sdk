// Package d4 provides Modern compliant chunked encryption system
package d4

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/DataDog/go-secure-sdk/crypto/canonicalization"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// D4 provides file content encryption/decryption algorithm based on HKDF_SHA256
// for Key wrapping and ChaCha20-Poly1305 to accomplish encryption for
// confidentiality and authentication for integrity of each chunk.
//
// The key leak risks are reduced due to the fact that each operation has its
// own derived keys for encryption and authentication.
//
// This algorithm version is NOT FIPS compliant.

const (
	minKeyLen            = 32
	nonceLen             = 32
	encryptionKeyLen     = 32
	encryptionNonceLen   = 32
	MagicVersion         = 0xD4
	chunkSize            = 64 * 1024
	encodedContentLength = 4
	// Magic(1B) || Nonce (32B) || ChunkSize Tag (1B)
	headerSize = 34
)

// -----------------------------------------------------------------------------

// EncryptedLength returns the encrypted length matching the plaintext length.
func EncryptedLength(plaintextLength int) int {
	dataChunkSize := chunkSize - chacha20poly1305.Overhead - encodedContentLength
	dataChunkCount := int(float64(plaintextLength) / float64(dataChunkSize))
	dataTrailer := plaintextLength % dataChunkSize

	switch {
	case dataTrailer > 0:
		return headerSize + dataChunkCount*chunkSize + encodedContentLength + dataTrailer + chacha20poly1305.Overhead
	default:
		return headerSize + dataChunkCount*chunkSize
	}
}

// Encrypt the given plaintext with the given key using HKDF_SHA256+CHACHA20-POLY1305.
// The keys are derived using HKDF_SHA-256 to ensure a sufficient entropy for
// the encryption and the authentication.
func Encrypt(dst io.Writer, plaintext io.Reader, key []byte) error {
	return encrypt(rand.Reader, key, plaintext, nil, dst)
}

// EncryptWithAdditionalData encrypts the given plaintext with the given key and
// adds the given additional data to the authentication context.
// In order to decrypt the result of this function, the same additional data
// must be provided to the `DecryptWithAdditionalData` function.
func EncryptWithAdditionalData(dst io.Writer, plaintext io.Reader, key, aad []byte) error {
	return encrypt(rand.Reader, key, plaintext, aad, dst)
}

// Decrypt the given ciphertext with the given key using HKDF_SHA256+CHACHA20-POLY1305.
func Decrypt(dst io.Writer, ciphertext io.Reader, key []byte) error {
	return decrypt(key, ciphertext, nil, dst)
}

// DecryptWithAdditionalData decrypts the given ciphertext with the given key and
// uses the additianl data during authentication.
func DecryptWithAdditionalData(dst io.Writer, ciphertext io.Reader, key, aad []byte) error {
	return decrypt(key, ciphertext, aad, dst)
}

// -----------------------------------------------------------------------------

func encrypt(rand io.Reader, key []byte, plaintext io.Reader, aad []byte, out io.Writer) error {
	// Check arguments
	if len(key) < minKeyLen {
		return errors.New("key must be 32 bytes long at least")
	}
	if plaintext == nil {
		return errors.New("plaintext reader must not be nil")
	}
	if out == nil {
		return errors.New("output writer must not be nil")
	}

	// Wrap plaintext reader
	plaintext = bufio.NewReaderSize(plaintext, chunkSize)

	// Magic (1B) || Nonce (32B) || ChunkSize (1B) || ( BLOCK (ChunkSize B) )*
	// Write magic
	if _, err := out.Write([]byte{MagicVersion}); err != nil {
		return fmt.Errorf("unable to write magic: %w", err)
	}

	// Generate random nonce
	var nonce [nonceLen]byte
	if _, err := io.ReadFull(rand, nonce[:]); err != nil {
		return fmt.Errorf("unable to generate nonce: %w", err)
	}

	// Write nonce
	if _, err := out.Write(nonce[:]); err != nil {
		return fmt.Errorf("unable to write nonce: %w", err)
	}

	// Write chunksize (fixed to 64Kb for the moment)
	if _, err := out.Write([]byte{0x01}); err != nil {
		return fmt.Errorf("unable to write chunk size: %w", err)
	}

	// Derive all key materials
	var eK [encryptionKeyLen + encryptionNonceLen]byte
	h := hkdf.New(sha256.New, key, nonce[:], []byte("datadog-chunk-encryption-keys-v2"))
	if _, err := io.ReadFull(h, eK[:]); err != nil {
		return fmt.Errorf("unable to derive encryption master key: %w", err)
	}

	// Initialize ChaCha20-Poly1305 AEAD
	aead, err := chacha20poly1305.New(eK[:encryptionKeyLen])
	if err != nil {
		return fmt.Errorf("unable to initialize strream cipher: %w", err)
	}

	// Prepare nonce derivation function
	nhm := hmac.New(sha256.New, eK[encryptionKeyLen:])

	chunkCounter := uint64(1)
	var chunkCounterRaw [8]byte
	chunkRaw := make([]byte, chunkSize-aead.Overhead(), chunkSize)
	final := make([]byte, 1)

	for {
		// Length (4B) || Content (*B)
		binary.BigEndian.PutUint64(chunkCounterRaw[:], chunkCounter)

		// Read a plaintext chunk. The read result is stored starting at the 5th
		// byte.
		// The 4 first bytes are used to encode the content length and prevent
		// content reallocation.
		n, err := io.ReadFull(plaintext, chunkRaw[encodedContentLength:])
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				// Empty plaintext
			case errors.Is(err, io.ErrUnexpectedEOF):
				// Truncated read (buffer can't be filled to its capacity)
			default:
				return fmt.Errorf("unable to read plaintext content: %w", err)
			}
		}
		if n < chunkSize-4-aead.Overhead() {
			final[0] = 0x01
		}

		// Ensure no state conservation
		nhm.Reset()
		nhm.Write([]byte("datadog-chunked-encryption-nonce-v2")) // Purpose
		nhm.Write(chunkCounterRaw[:])                            // Chunk counter
		nhm.Write(final)                                         // Is final flag
		nonce := nhm.Sum(nil)

		// Prepare chunk
		binary.BigEndian.PutUint32(chunkRaw[:encodedContentLength], uint32(n))

		// Compute AAD
		chunkAad, err := canonicalization.PreAuthenticationEncoding(
			[]byte("datadog-chunked-encryption-aad-v2"),
			// Bind chunk counter as AAD to prevent chunk reordering.
			chunkCounterRaw[:],
			final,
			aad,
		)
		if err != nil {
			return fmt.Errorf("unable to pack chunk additional data: %w", err)
		}

		// Seal the chunk content
		ciphertext := aead.Seal(chunkRaw[:0], nonce[:aead.NonceSize()], chunkRaw[:encodedContentLength+n], chunkAad)

		// Encrypt the raw prepared chunk content.
		if _, err := out.Write(ciphertext[:encodedContentLength+n+aead.Overhead()]); err != nil {
			return fmt.Errorf("unable to write chunk content: %w", err)
		}

		if final[0] == 0x01 {
			break
		}

		// Increment chunck counter
		chunkCounter = chunkCounter + 1
	}

	return nil
}

func decrypt(key []byte, ciphertext io.Reader, aad []byte, out io.Writer) error {
	// Check arguments
	if len(key) < minKeyLen {
		return errors.New("key must be 32 bytes long at least")
	}
	if ciphertext == nil {
		return errors.New("ciphertext reader must not be nil")
	}
	if out == nil {
		return errors.New("output writer must not be nil")
	}

	// Wrap plaintext reader
	ciphertext = bufio.NewReaderSize(ciphertext, chunkSize)

	// Read header
	// 	Magic (1B) || Nonce (32B) || ChunkSize (1B) || ( BLOCK (ChunkSize B) )*
	var headers [2 + nonceLen]byte
	if _, err := ciphertext.Read(headers[:]); err != nil {
		return fmt.Errorf("unable to read ciphertext headers: %w", err)
	}

	// Ensure supported version
	if headers[0] != MagicVersion {
		return errors.New("unsupported encryption container version")
	}

	var (
		nonce        = headers[1 : 1+nonceLen]
		chunkSizeTag = headers[1+nonceLen:][0]
	)

	// Ensure right chunk size
	if chunkSizeTag != 0x01 {
		return errors.New("unsupported encryption chunk size")
	}

	// Derive all key materials
	var eK [encryptionKeyLen + encryptionNonceLen]byte
	h := hkdf.New(sha256.New, key, nonce[:], []byte("datadog-chunk-encryption-keys-v2"))
	if _, err := io.ReadFull(h, eK[:]); err != nil {
		return fmt.Errorf("unable to derive encryption master key: %w", err)
	}

	// Initialize ChaCha20-Poly1305 AEAD
	aead, err := chacha20poly1305.New(eK[:encryptionKeyLen])
	if err != nil {
		return fmt.Errorf("unable to initialize strream cipher: %w", err)
	}

	// Prepare nonce derivation function
	nhm := hmac.New(sha256.New, eK[encryptionKeyLen:])

	chunkCounter := uint64(1)
	var chunkCounterRaw [8]byte
	chunkRaw := make([]byte, chunkSize)
	final := make([]byte, 1)

	for {
		// Read a ciphertext chunk
		n, err := io.ReadFull(ciphertext, chunkRaw[:])
		if err != nil {
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("unable to read ciphertext content: %w", err)
			}
		}
		if n < encodedContentLength+aead.Overhead() {
			return errors.New("invalid chunk size")
		}
		if n < chunkSize-encodedContentLength-aead.Overhead() {
			final[0] = 0x01
		}

		// Prepare chunk counter
		binary.BigEndian.PutUint64(chunkCounterRaw[:], chunkCounter)

		// Ensure no state conservation
		nhm.Reset()
		nhm.Write([]byte("datadog-chunked-encryption-nonce-v2")) // Purpose
		nhm.Write(chunkCounterRaw[:])                            // Chunk counter
		nhm.Write(final)                                         // Is final flag
		nonce := nhm.Sum(nil)

		// Compute AAD
		chunkAad, err := canonicalization.PreAuthenticationEncoding(
			[]byte("datadog-chunked-encryption-aad-v2"),
			// Bind chunk counter as AAD to prevent chunk reordering.
			chunkCounterRaw[:],
			final,
			aad,
		)
		if err != nil {
			return fmt.Errorf("unable to pack chunk additional data: %w", err)
		}

		// Decrypt the given chunk
		if _, err := aead.Open(chunkRaw[:0], nonce[:aead.NonceSize()], chunkRaw[:n], chunkAad); err != nil {
			return fmt.Errorf("unable to decrypt chunk: %w", err)
		}

		// Extract plaintext
		contentLength := binary.BigEndian.Uint32(chunkRaw[:4])

		// Write to output writer
		if _, err := out.Write(chunkRaw[encodedContentLength : encodedContentLength+contentLength]); err != nil {
			return fmt.Errorf("unable to write plaintext to output writer: %w", err)
		}

		// Check final flag
		if final[0] == 0x01 {
			break
		}

		// Increment chunk counter
		chunkCounter = chunkCounter + 1
	}

	return nil
}
