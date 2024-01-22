package hasher

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// Metadata represents hasher result
type Metadata struct {
	_ struct{} `cbor:",toarray"`

	Algorithm uint8  `cbor:"1,keyasint"`
	Version   uint8  `cbor:"2,keyasint"`
	Salt      []byte `cbor:"3,keyasint"`
	Hash      []byte `cbor:"4,keyasint"`
}

// Pack metadata as BASE64URL CBOR payload
func (m *Metadata) Pack() (string, error) {
	// Encode as CBOR
	payload, err := cbor.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("unable to serialize metadata: %w", err)
	}

	// Return encoded struct
	return base64.RawStdEncoding.EncodeToString(payload), nil
}

// Decode metadata from string
func Decode(r io.Reader) (*Metadata, error) {
	// Check arguments
	if r == nil {
		return nil, errors.New("reader must not be nil")
	}

	// Decode as list
	meta := &Metadata{}
	if err := cbor.NewDecoder(base64.NewDecoder(base64.RawStdEncoding, io.LimitReader(r, 138))).Decode(meta); err != nil {
		return nil, fmt.Errorf("unable to decode metadata: %w", err)
	}

	// Rebuild metadata instance
	return meta, nil
}
