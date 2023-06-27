// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package transformer

// Identity initializes a transformer which doesn't alter the given value.
func Identity() Transformer {
	return &identityTransformer{}
}

// -----------------------------------------------------------------------------
type identityTransformer struct{}

func (t *identityTransformer) Encode(raw []byte) ([]byte, error) {
	return raw, nil
}

func (t *identityTransformer) Decode(raw []byte) ([]byte, error) {
	return raw, nil
}
