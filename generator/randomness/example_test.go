// SPDX-FileCopyrightText: 2024-Present Datadog, Inc
// SPDX-License-Identifier: Apache-2.0

package randomness

func ExampleCryptoSeed() {
	// Usign rand.Seed is deprecated since Go 1.20.
	// Initialize the concurrent usage safe PRNG math/rand with a CSPRNG sourced random integer.
	prng := NewLockedRand(CryptoSeed())

	// Generate a random number between 0 and 99
	prng.Intn(100)
}
