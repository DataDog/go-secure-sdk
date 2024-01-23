package randomness

import (
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

func ExampleDRNG() {
	// This password is sensitive and must be protected as a sensitive secret
	masterPassword := []byte(`GnvPu^vA&WrIS8.;|UvYAR2PT8g&HJUL|;}qC3kw\6:R/Gkh2%e^&cs#5el8ak;`)
	purpose := "autorotating-envelope-signature-keypair-generation"

	// Stretch the masterPassword with the purpose to retrieve a DRNG seed
	seed := pbkdf2.Key(masterPassword, []byte(purpose), 4096, drngSeedLength, sha512.New)

	// Initialize a DRNG from the master seed and the purpose
	drng, err := DRNG(seed, "signature-keypair-for-2023-02-01")
	if err != nil {
		panic(err)
	}

	// Generate a deterministic keypair based on the master seed and the purpose.
	// So that you don't have to handle to storage of this crypto materials.
	// Imagine something like deterministic daily key rotation without initial
	// key exchange, etc.
	pub, sk, err := ed25519.GenerateKey(drng)
	if err != nil {
		panic(err)
	}

	// Output:
	// pub: 95e5c0f481e71146eef4b4a1d05e3c09294952a48700068dea29f133490b4a90
	// sk: 14531fe31a69d5de47b9ebb2a187f4dd9f0cb0426151253d0b063b07ecb036c595e5c0f481e71146eef4b4a1d05e3c09294952a48700068dea29f133490b4a90
	fmt.Printf("pub: %x\nsk: %x", pub, sk)
}

func ExampleCryptoSeed() {
	// Usign rand.Seed is deprecated since Go 1.20.
	// Initialize the concurrent usage safe PRNG math/rand with a CSPRNG sourced random integer.
	prng := NewLockedRand(CryptoSeed())

	// Generate a random number between 0 and 99
	prng.Intn(100)
}
