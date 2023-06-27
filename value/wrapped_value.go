// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package value

import (
	"database/sql"
	"database/sql/driver"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/DataDog/go-secure-sdk/value/transformer"
)

// -----------------------------------------------------------------------------

var (
	_ encoding.BinaryMarshaler   = (*Wrapped[string])(nil)
	_ encoding.BinaryUnmarshaler = (*Wrapped[string])(nil)
	_ encoding.TextMarshaler     = (*Wrapped[string])(nil)
	_ encoding.TextUnmarshaler   = (*Wrapped[string])(nil)
	_ json.Marshaler             = (*Wrapped[string])(nil)
	_ json.Unmarshaler           = (*Wrapped[string])(nil)
	_ driver.Valuer              = (*Wrapped[string])(nil)
	_ sql.Scanner                = (*Wrapped[string])(nil)
	_ fmt.Stringer               = (*Wrapped[string])(nil)
	_ fmt.Formatter              = (*Wrapped[string])(nil)
	_ fmt.GoStringer             = (*Wrapped[string])(nil)
)

// AsWrapped wraps a given value as a secret.
func AsWrapped[T any](value T, t transformer.Transformer) Wrapped[T] {
	return Wrapped[T]{
		value: value,
		t:     t,
	}
}

// -----------------------------------------------------------------------------

// Wrapped describes sensitive string value.
type Wrapped[T any] struct {
	value T `json:"-" xml:"-" yaml:"-" msgpack:"-" cbor:"-"`
	t     transformer.Transformer
}

// MarshalBinary marshals the secreat as a encrypted byte array.
// Implements encoding.BinaryMarshaler.
func (s Wrapped[T]) MarshalBinary() ([]byte, error) {
	// Marshal as JSON
	payload, err := json.Marshal(s.value)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize value as JSON: %w", err)
	}

	// Apply transformation
	out, err := s.t.Encode(payload)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal value as binary: %w", err)
	}

	return out, nil
}

// UnmarshalBinary unmarshals a sealed secret and rturnts the decrypted value.
// Implements encoding.BinaryUnmarshaler.
func (s *Wrapped[T]) UnmarshalBinary(in []byte) error {
	// Revert transformation
	payload, err := s.t.Decode(in)
	if err != nil {
		return fmt.Errorf("unable to unmarshal from binary: %w", err)
	}

	// Unpack from JSON
	if err := json.Unmarshal(payload, &s.value); err != nil {
		return fmt.Errorf("unable to unmarshal protected content: %w", err)
	}

	return nil
}

// MarshalText marshals the secret as a encrypted text.
// Implements encoding.TextMarshaler
func (s Wrapped[T]) MarshalText() ([]byte, error) {
	// Delegate to MarshalBinary
	out, err := s.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("unable to marshal value: %w", err)
	}

	return []byte(base64.RawURLEncoding.EncodeToString(out)), nil
}

// UnmarshalText unmarshals a sealed secret and rturnts the decrypted value.
// Implements encoding.TextUnmarshaler.
func (s *Wrapped[T]) UnmarshalText(in []byte) error {
	// Decode Base64
	raw, err := base64.RawURLEncoding.DecodeString(string(in))
	if err != nil {
		return fmt.Errorf("invalid base64 encoding detected: %w", err)
	}

	// Delegate to UnmarshalBinary
	return s.UnmarshalBinary(raw)
}

// MarshalJSON marshals the string as a redacted one.
// Implements json.Marshaler
func (s Wrapped[T]) MarshalJSON() ([]byte, error) {
	out, err := s.MarshalText()
	if err != nil {
		return nil, fmt.Errorf("unable to seal secret: %w", err)
	}

	// Encoded the transformed value
	encoded, err := json.Marshal(string(out))
	if err != nil {
		return nil, fmt.Errorf("unable to encode transformed value as JSON: %w", err)
	}

	return encoded, nil
}

// UnmarshalJSON unmarshals the secret from the encrypted value.
// Implements json.Marshaler
func (s *Wrapped[T]) UnmarshalJSON(in []byte) error {
	var payload string
	if err := json.Unmarshal(in, &payload); err != nil {
		return fmt.Errorf("unable to deocde JSON: %w", err)
	}

	return s.UnmarshalText([]byte(payload))
}

// Value marshals the sealed secret to be stored in a string column record.
// Implements driver.Valuer.
func (s Wrapped[T]) Value() (driver.Value, error) {
	// Marshal as text
	out, err := s.MarshalText()
	if err != nil {
		return nil, fmt.Errorf("unable to seal secret value: %w", err)
	}

	return string(out), nil
}

// Scan unmarshals a secret secret from a SQL record.
// Implements sql.Scanner.
func (s *Wrapped[T]) Scan(src interface{}) error {
	var err error
	switch in := src.(type) {
	case string: // expect a base64 encoded string
		err = s.UnmarshalText([]byte(in))
	default:
		return fmt.Errorf("incompatible type %T", src)
	}

	return err
}

// String implements string interface.
// Implements xml.Marshaler
func (s Wrapped[T]) String() string {
	return string(redactedToken)
}

// GoString implements alternative string interface.
// Implements fmt.GoStringer
func (s Wrapped[T]) GoString() string {
	return string(redactedToken)
}

// Format implements string formatter.
// Implements fmt.Formatter
func (s Wrapped[T]) Format(f fmt.State, c rune) {
	out, err := s.MarshalText()
	if err != nil {
		panic(err)
	}
	if _, err := f.Write(out); err != nil {
		panic(err)
	}
}

// Unwrap returns the wrapped secret value.
func (s *Wrapped[T]) Unwrap() T {
	return s.value
}
