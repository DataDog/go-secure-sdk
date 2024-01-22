package transformer

import (
	"errors"
	"fmt"
	"hash"
)

// Hash initializes a transformer
func Hash(hasher func() hash.Hash) Transformer {
	return &hashTransformer{
		hasher: hasher,
	}
}

// -----------------------------------------------------------------------------
type hashTransformer struct {
	hasher func() hash.Hash
}

func (t *hashTransformer) Encode(raw []byte) ([]byte, error) {
	// Initialize a new hash instance
	h := t.hasher()
	if h == nil {
		return nil, errors.New("hash builder function returned a nil instance")
	}

	// Write the input
	if _, err := h.Write(raw); err != nil {
		return nil, fmt.Errorf("unable to compute value hash: %w", err)
	}

	return h.Sum(nil), nil
}

func (t *hashTransformer) Decode(raw []byte) ([]byte, error) {
	return nil, ErrImpossibleOperation
}
