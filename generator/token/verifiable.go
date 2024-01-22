package token

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"regexp"
	"strings"
)

var (
	defaultRandomLength = 22
	defaultTokenLength  = 36
	defaultSeparator    = "_"
	nonAuthorizedChars  = regexp.MustCompile("[^a-z0-9-]")
)

// VerifiableRandom returns a verifiable random string generator.
// This implementation uses a CRC32C (Castagnoli seed) to distinguish fully
// random string.
//
// To prevent token swapping risk, we recommend you to use VerifiableRandomWithPurpose()
// function with a dedicated purpose string.
//
// This should not be used as a cryptographic proof. A digital signature process
// is encouraged to provide provenance authenticity.
func VerifiableRandom() VerifiableGenerator {
	return VerifiableRandomWithPurpose("")
}

// VerifiableRandomWithPurpose returns a verifiable random string generator
// associated to a dedicated purpose. All generated tokens are bound to this
// specified purpose and can't be verified without the same purpose value.
//
// This should not be used as a cryptographic proof. A digital signature process
// is encouraged to provide provenance authenticity.
func VerifiableRandomWithPurpose(purpose string) VerifiableGenerator {
	var h []byte

	// Normalize purpose
	purpose = strings.TrimSpace(strings.ToLower(purpose))
	if purpose != "" {
		// Ensure a fixed-length purpose
		purposeH := sha256.Sum256([]byte(purpose))
		h = make([]byte, 32)
		copy(h, purposeH[:])
	}

	return &verifiableRandomGenerator{
		crcTable:   crc32.MakeTable(crc32.Castagnoli),
		randReader: rand.Reader,
		purpose:    h,
	}
}

// -----------------------------------------------------------------------------

// GenerateOption is used to set up the token generation process.
type GenerateOption func(*generateOption)

// generateOption holds the generation settings.
type generateOption struct {
	prefix string
}

// WithTokenPrefix prepends the given prefix to the token generation so that it
// will be covered by the checksum.
//
// Prefix must match [a-z0-9-]+ regular expression (lowercase kebab case).
func WithTokenPrefix(value string) GenerateOption {
	return func(o *generateOption) {
		o.prefix = strings.TrimSpace(strings.ToLower(value))
	}
}

// -----------------------------------------------------------------------------

type verifiableRandomGenerator struct {
	crcTable   *crc32.Table
	randReader io.Reader
	purpose    []byte
}

func (vr *verifiableRandomGenerator) Generate(opts ...GenerateOption) (string, error) {
	// Prepare default settings
	dopts := &generateOption{}
	for _, o := range opts {
		o(dopts)
	}

	// Generate random string
	buf := make([]byte, defaultRandomLength)
	if _, err := io.ReadFull(vr.randReader, buf); err != nil {
		return "", fmt.Errorf("unable to generate random token: %w", err)
	}

	// Prepare token prefix
	prefix := ""
	if dopts.prefix != "" {
		// Ensure prefix syntax
		if nonAuthorizedChars.MatchString(dopts.prefix) {
			return "", fmt.Errorf("the given prefix %q contains forbidden characters, (0-9a-z-) are allowed", dopts.prefix)
		}
		prefix = dopts.prefix + defaultSeparator
	}

	// Prepend the prefix
	protected := append([]byte(prefix), buf...)

	// Inject purpose if specified
	if len(vr.purpose) > 0 {
		protected = append(protected, vr.purpose...)
	}

	// Compute checksum CRC32C (Use Castagnoli seed)
	chksm := crc32.Checksum(protected, vr.crcTable)

	// Marshal to byte
	var sigRaw [4]byte
	binary.BigEndian.PutUint32(sigRaw[:], chksm)

	// Encode final - BASE62 is used to exclude the prefix separator.
	final := toPaddedBase62(append(buf, sigRaw[:]...), defaultTokenLength)

	// Encode token (base62)
	return prefix + final, nil
}

func (vr *verifiableRandomGenerator) Verify(in string) error {
	// Detect prefix usage
	var prefix string
	if parts := strings.SplitN(in, defaultSeparator, 2); len(parts) == 2 {
		prefix = parts[0] + defaultSeparator
		in = parts[1]
	}

	// Check token length
	if len(in) != defaultTokenLength {
		return errors.New("invalid token length")
	}

	// Decode base62
	raw, err := parsePaddedBase62(in, defaultRandomLength+4)
	if err != nil {
		return fmt.Errorf("invalid token format: %w", err)
	}

	// Protected
	protected := append([]byte(prefix), raw[:defaultRandomLength]...)

	// Inject purpose if specified
	if len(vr.purpose) > 0 {
		protected = append(protected, vr.purpose...)
	}

	// Ensure checksum
	chksm := crc32.Checksum(protected, vr.crcTable)

	// Marshal to byte
	var sigRaw [4]byte
	binary.BigEndian.PutUint32(sigRaw[:], chksm)
	if !bytes.Equal(sigRaw[:], raw[defaultRandomLength:]) {
		return ErrTokenNotAuthenticated
	}

	// No error
	return nil
}
