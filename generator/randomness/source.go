// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package randomness

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// CryptoSeed returns a seed using crypto/rand. On error, the function generates
// a panic with the error.
func CryptoSeed() int64 {
	var seed int64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &seed); err != nil {
		panic(fmt.Errorf("failed to initialize the crypto/rand seed: %v", err))
	}
	return seed
}
