// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"errors"

	"github.com/DataDog/go-secure-sdk/crypto/signature"
	protectedv2 "github.com/DataDog/go-secure-sdk/crypto/signature/envelope/internal/v2"
)

// ErrInvalidEnvelope is raised when there is an issue with the envelope.
var ErrInvalidEnvelope = errors.New("invalid envelope")

const (
	// SigningVersion point to the version used for signing purpose.
	SigningVersion = protectedv2.Version
	// LowestSupportedVersion defines the minimal version used for envelope
	// verification.
	LowestSupportedVersion = SigningVersion - 1
)

// Envelope describes the final assembled message
type Envelope struct {
	ContentType string     `json:"content_type"`
	Content     []byte     `json:"content"`
	Signature   *Signature `json:"signature"`
}

// Signature holds all signature elements.
type Signature struct {
	Version     uint8               `json:"version"`
	Algorithm   signature.Algorithm `json:"algorithm"`
	PublicKeyID []byte              `json:"pubkey"`
	Timestamp   uint64              `json:"timestamp"`
	Proof       []byte              `json:"proof"`
	// Deprecated: V2 ignore this value during protected content computation.
	Nonce []byte `json:"nonce,omitempty"`
}
