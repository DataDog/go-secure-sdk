package hpke

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
)

var (
	defaultPSK   = []byte("")
	defaultPSKID = []byte("")
)

// Exporter describes key derivation operation.
type Exporter interface {
	Export(exporterContext []byte, length uint16) ([]byte, error)
}

type context struct {
	suite          *cipherSuite
	aead           cipher.AEAD
	sharedSecret   []byte
	keyScheduleCtx []byte
	secret         []byte
	key            []byte
	baseNonce      []byte
	counter        *atomic.Uint64
	exporterSecret []byte
}

func (s *cipherSuite) verifyPSKInputs(encMode mode, psk, pskID []byte) error {
	gotPsk := !bytes.Equal(psk, defaultPSK)
	gotPskID := !bytes.Equal(pskID, defaultPSKID)

	// Check arguments
	switch {
	case gotPsk && !gotPskID, !gotPsk && gotPskID:
		return errors.New("inconsistent PSK inputs")
	default:
	}

	switch encMode {
	case modeBase, modeAuth:
		if gotPsk {
			return errors.New("PSK input provided when not needed")
		}
	case modePsk, modeAuthPsk:
		if !gotPsk {
			return errors.New("missing required PSK input")
		}
	}

	return nil
}

func (s *cipherSuite) keySchedule(encMode mode, sharedSecret, info, psk, pskID []byte) (*context, error) {
	// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2.1-4
	switch {
	case len(info) > 64:
		return nil, fmt.Errorf("info must not be larger than 64 bytes")
	case len(psk) > 64:
		return nil, fmt.Errorf("psk must not be larger than 64 bytes")
	case len(pskID) > 64:
		return nil, fmt.Errorf("pskID must not be larger than 64 bytes")
	}

	if err := s.verifyPSKInputs(encMode, psk, pskID); err != nil {
		return nil, err
	}

	pskIDHash := s.labeledExtract([]byte(""), []byte("psk_id_hash"), pskID)
	infoHash := s.labeledExtract([]byte(""), []byte("info_hash"), info)

	// key_schedule_context = concat(mode, psk_id_hash, info_hash)
	keyScheduleContext := append([]byte{}, byte(encMode))
	keyScheduleContext = append(keyScheduleContext, pskIDHash...)
	keyScheduleContext = append(keyScheduleContext, infoHash...)

	secret := s.labeledExtract(sharedSecret, []byte("secret"), psk)

	var (
		aead           cipher.AEAD
		key, baseNonce []byte
	)
	if s.aeadID != AEAD_EXPORT_ONLY {
		var err error

		key, err = s.labeledExpand(secret, []byte("key"), keyScheduleContext, s.aeadID.KeySize())
		if err != nil {
			return nil, fmt.Errorf("unable to derive encryption key: %w", err)
		}
		aead, err = s.aeadID.New(key)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize AEAD encryption: %w", err)
		}

		baseNonce, err = s.labeledExpand(secret, []byte("base_nonce"), keyScheduleContext, s.aeadID.NonceSize())
		if err != nil {
			return nil, fmt.Errorf("unable to derive base nonce: %w", err)
		}
	}

	exporterSecret, err := s.labeledExpand(secret, []byte("exp"), keyScheduleContext, s.kdfID.ExtractSize())
	if err != nil {
		return nil, fmt.Errorf("unable to derive exporter secret: %w", err)
	}

	return &context{
		suite:          s,
		aead:           aead,
		sharedSecret:   sharedSecret,
		keyScheduleCtx: keyScheduleContext,
		secret:         secret,
		key:            key,
		baseNonce:      baseNonce,
		counter:        &atomic.Uint64{},
		exporterSecret: exporterSecret,
	}, nil
}

func (c *context) Seal(plaintext, aad []byte) ([]byte, error) {
	if c.suite.aeadID == AEAD_EXPORT_ONLY {
		return nil, errors.New("seal operation not available in export only mode")
	}

	ct := c.aead.Seal(nil, c.computeNonce(c.counter.Load()), plaintext, aad)
	if err := c.incrementCounter(); err != nil {
		c.wipeBytes(ct)
		return nil, err
	}

	return ct, nil
}

func (c *context) Open(ciphertext, aad []byte) ([]byte, error) {
	if c.suite.aeadID == AEAD_EXPORT_ONLY {
		return nil, errors.New("open operation not available in export only mode")
	}

	pt, err := c.aead.Open(nil, c.computeNonce(c.counter.Load()), ciphertext, aad)
	if err != nil {
		return nil, err
	}

	if err := c.incrementCounter(); err != nil {
		c.wipeBytes(pt)
		return nil, err
	}

	return pt, nil
}

func (c *context) Export(exporterContext []byte, outputLen uint16) ([]byte, error) {
	// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2.1-4
	if len(exporterContext) > 64 {
		return nil, errors.New("exporter context must be less than 64 bytes")
	}
	return c.suite.labeledExpand(c.exporterSecret, []byte("sec"), exporterContext, outputLen)
}

func (c *context) wipeBytes(buf []byte) {
	// clear(buf) - Go 1.21
	for i := range buf {
		buf[i] = 0
	}
}

func (c *context) computeNonce(seq uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, seq)
	nonce := make([]byte, c.aead.NonceSize())
	copy(nonce, c.baseNonce)
	for i := range buf {
		// Apply XOR on last 8 bytes only.
		nonce[c.aead.NonceSize()-8+i] ^= buf[i]
	}

	return nonce
}

func (c *context) incrementCounter() error {
	if c.counter.Load() >= (1<<(8*c.aead.NonceSize()))-1 {
		return errors.New("message limit reached")
	}
	c.counter.Add(1)

	return nil
}
