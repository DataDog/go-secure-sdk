// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package passphrase

import (
	"fmt"
	"strings"

	"github.com/sethvargo/go-diceware/diceware"
)

const (
	// MinWordCount defines the lowest bound for allowed word count.
	MinWordCount = 4
	// MaxWordCount defines the highest bound for allowed word count.
	MaxWordCount = 24
	// BasicWordCount defines basic passphrase word count (4 words).
	BasicWordCount = 4
	// StrongWordCount defines strong passphrase word count (8 words).
	StrongWordCount = 8
	// ParanoidWordCount defines paranoid passphrase word count (12 words).
	ParanoidWordCount = 12
	// MasterWordCount defines master passphrase word count (24 words).
	MasterWordCount = 24
)

// Diceware generates a passphrase using english words.
func Diceware(count int) (string, error) {
	// Check parameters
	if count < MinWordCount {
		count = MinWordCount
	}
	if count > MaxWordCount {
		count = MaxWordCount
	}

	// Generate word list
	list, err := diceware.Generate(count)
	if err != nil {
		return "", fmt.Errorf("unable to generate daceware passphrase: %w", err)
	}

	// Assemble result
	return strings.Join(list, "-"), nil
}

// Basic generates 4 words diceware passphrase.
func Basic() (string, error) {
	return Diceware(BasicWordCount)
}

// Strong generates 8 words diceware passphrase.
func Strong() (string, error) {
	return Diceware(StrongWordCount)
}

// Paranoid generates 12 words diceware passphrase.
func Paranoid() (string, error) {
	return Diceware(ParanoidWordCount)
}

// Master generates 24 words diceware passphrase.
func Master() (string, error) {
	return Diceware(MasterWordCount)
}
