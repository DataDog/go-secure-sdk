// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package value

import (
	"encoding"
	"encoding/json"
	"fmt"
)

// -----------------------------------------------------------------------------

const redactedToken = "[redacted]"

var (
	_ encoding.BinaryMarshaler = (*Redacted[string])(nil)
	_ encoding.TextMarshaler   = (*Redacted[string])(nil)
	_ json.Marshaler           = (*Redacted[string])(nil)
	_ fmt.Stringer             = (*Redacted[string])(nil)
	_ fmt.Formatter            = (*Redacted[string])(nil)
	_ fmt.GoStringer           = (*Redacted[string])(nil)
)

// AsRedacted wraps a given value as a redacted value.
func AsRedacted[T any](value T) Redacted[T] {
	return Redacted[T]{
		value: value,
	}
}

// -----------------------------------------------------------------------------

// Redacted describes a redacted value to prevnt its leak.
type Redacted[T any] struct {
	value T `json:"-" xml:"-" yaml:"-" msgpack:"-" cbor:"-"`
}

// MarshalBinary marshals the secreat as a redacted text.
// Implements encoding.BinaryMarshaler.
func (Redacted[T]) MarshalBinary() ([]byte, error) {
	return []byte(redactedToken), nil
}

// MarshalText marshals the secret as a redacted text.
// Implements encoding.TextMarshaler
func (Redacted[T]) MarshalText() ([]byte, error) {
	return []byte(redactedToken), nil
}

// MarshalJSON marshals the string as a redacted one.
// Implements json.Marshaler
func (Redacted[T]) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", redactedToken)), nil
}

// String implements string interface.
// Implements fmt.Stringer
func (Redacted[T]) String() string {
	return redactedToken
}

// GoString implements alternative string interface.
// Implements fmt.GoStringer
func (Redacted[T]) GoString() string {
	return redactedToken
}

// Format implements string formatter.
// Implements fmt.Formatter
func (Redacted[T]) Format(f fmt.State, c rune) {
	if _, err := f.Write([]byte(redactedToken)); err != nil {
		panic(err)
	}
}

// Unwrap returns the wrapped secret value.
func (s *Redacted[T]) Unwrap() T {
	return s.value
}
