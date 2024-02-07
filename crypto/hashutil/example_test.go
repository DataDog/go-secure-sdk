package hashutil

import (
	"crypto"
	// Import all hash functions
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"
	_ "golang.org/x/crypto/sha3"
)

func ExampleFileHash() {
	// Create a read-only filesystem
	root := os.DirFS("./testdata")

	// Compute SHA256 of the file
	h, err := FileHash(root, "1.txt", crypto.SHA256)
	if err != nil {
		panic(err)
	}

	// Output: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	fmt.Println(hex.EncodeToString(h))
}

func ExampleFileHashes() {
	// Create a read-only filesystem
	root := os.DirFS("./testdata")

	// Compute multiple hash in one read
	res, err := FileHashes(root, "1.txt",
		// BLAKE2b (golang.org/x/crypto/blake2b) NON-FIPS
		crypto.BLAKE2b_256, crypto.BLAKE2b_384, crypto.BLAKE2b_512,
		// BLAKE2s (golang.org/x/crypto/blake2s) NON-FIPS
		crypto.BLAKE2s_256,
		// SHA2
		crypto.SHA256, crypto.SHA384, crypto.SHA512,
		// SHA3 (golang.org/x/crypto/sha3)
		crypto.SHA3_256, crypto.SHA3_384, crypto.SHA3_512,
	)
	if err != nil {
		panic(err)
	}

	// Sort map keys for stable output
	keys := make([]crypto.Hash, 0, len(res))
	for k := range res {
		keys = append(keys, k)
	}
	sort.SliceStable(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })

	// Output:
	// BLAKE2b-256 => bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319
	// BLAKE2b-384 => 6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4
	// BLAKE2b-512 => ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923
	// BLAKE2s-256 => 508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982
	// SHA-256 => ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	// SHA-384 => cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
	// SHA-512 => ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
	// SHA3-256 => 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
	// SHA3-384 => ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25
	// SHA3-512 => b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0
	for _, k := range keys {
		fmt.Printf("%s => %s\n", k.String(), hex.EncodeToString(res[k]))
	}
}

func ExampleHash() {
	// Compute SHA256 of the reader content
	h, err := Hash(strings.NewReader("Hello World!"), crypto.BLAKE2b_256)
	if err != nil {
		panic(err)
	}

	// Output: bf56c0728fd4e9cf64bfaf6dabab81554103298cdee5cc4d580433aa25e98b00
	fmt.Println(hex.EncodeToString(h))
}

func ExampleHashes() {
	// Compute SHA256 of the reader content
	res, err := Hashes(strings.NewReader("Hello World!"), crypto.SHA256, crypto.SHA3_256, crypto.BLAKE2b_256)
	if err != nil {
		panic(err)
	}

	// Sort map keys for stable output
	keys := make([]crypto.Hash, 0, len(res))
	for k := range res {
		keys = append(keys, k)
	}
	sort.SliceStable(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })

	// Output:
	// BLAKE2b-256 => bf56c0728fd4e9cf64bfaf6dabab81554103298cdee5cc4d580433aa25e98b00
	// SHA-256 => 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
	// SHA3-256 => d0e47486bbf4c16acac26f8b653592973c1362909f90262877089f9c8a4536af
	for _, k := range keys {
		fmt.Printf("%s => %s\n", k.String(), hex.EncodeToString(res[k]))
	}
}
