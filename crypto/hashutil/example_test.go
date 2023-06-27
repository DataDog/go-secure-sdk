// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package hashutil

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
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
	res, err := FileHashes(root, "1.txt", crypto.SHA256, crypto.SHA384, crypto.SHA512)
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
	// SHA-256 => ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	// SHA-384 => cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
	// SHA-512 => ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
	for _, k := range keys {
		fmt.Printf("%s => %s\n", k.String(), hex.EncodeToString(res[k]))
	}
}

func ExampleHash() {
	// Compute SHA256 of the reader content
	h, err := Hash(strings.NewReader("Hello World!"), crypto.SHA256)
	if err != nil {
		panic(err)
	}

	// Output: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
	fmt.Println(hex.EncodeToString(h))
}

func ExampleHashes() {
	// Compute SHA256 of the reader content
	res, err := Hashes(strings.NewReader("Hello World!"), crypto.SHA256, crypto.SHA384, crypto.SHA512)
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
	// SHA-256 => 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
	// SHA-384 => bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a
	// SHA-512 => 861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8
	for _, k := range keys {
		fmt.Printf("%s => %s\n", k.String(), hex.EncodeToString(res[k]))
	}
}
