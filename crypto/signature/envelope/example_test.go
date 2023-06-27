// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"

	"github.com/DataDog/go-secure-sdk/crypto/signature"
	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

type AppInfo struct {
	_ struct{} `cbor:",toarray"`

	GitCommit string `cbor:"1,keyasint"`
	GitBranch string `cbor:"2,keyasint"`
	BuildDate string `cbor:"3,keyasint"`
	GoVersion string `cbor:"4,keyasint"`
	Version   string `cbor:"5,keyasint"`
}

func ExampleWrapAndSign() {
	// Generate deterministic key pair for demonstration purpose
	_, pk, err := ed25519.GenerateKey(randomness.NewLockedRand(1))
	if err != nil {
		panic(err)
	}

	// Create a signer instance from the given crypto material
	signer, err := signature.FromPrivateKey(pk)
	if err != nil {
		panic(err)
	}

	// Create a PB Message (this object is used as a sample PB struct)
	m := &AppInfo{
		GitCommit: "b0a4cfc9fd21252eaf5e2093b7088d5228eb2b47",
		GitBranch: "main",
		BuildDate: "2022-12-12T13:57:32Z",
		GoVersion: "1.20",
		Version:   "v1.0.2",
	}

	// Serialize as bytes
	payload, err := cbor.Marshal(m)
	if err != nil {
		panic(err)
	}

	// Wrap and sign the given content
	envelope, err := WrapAndSign(
		"types.datadoghq.com/v1/AppInfo", // The content type must be identifiable
		payload,                          // Body to be signed
		signer,                           // Signer instance to use to generate the signature
		WithTimestamp(1670850610),        // Fixed timestamp for determinism
	)
	if err != nil {
		panic(err)
	}

	// Output:
	// {"content_type":"types.datadoghq.com/v1/AppInfo","content":"hXgoYjBhNGNmYzlmZDIxMjUyZWFmNWUyMDkzYjcwODhkNTIyOGViMmI0N2RtYWludDIwMjItMTItMTJUMTM6NTc6MzJaZDEuMjBmdjEuMC4y","signature":{"version":2,"algorithm":"ed25519","pubkey":"Fx5o8C5vZr+f9lwTx12bK0ksL0DtYeBlB8uLInw5cNU=","timestamp":1670850610,"proof":"lQ+1B6mbw3UfIlCEGzfTCepGtlyjhtXe2hejZbyz8yPgiNK3+s51AJHRdIlHitcjuHzyevzTD8kU+NXdLSn7BQ=="}}
	if err := json.NewEncoder(os.Stdout).Encode(envelope); err != nil {
		panic(err)
	}
}

func ExampleVerifyAndUnwrap() {
	// Generate deterministic key pair for demonstration purpose
	pub, _, err := ed25519.GenerateKey(randomness.NewLockedRand(1))
	if err != nil {
		panic(err)
	}

	// Create a verifier instance from the given crypto material
	verifier, err := signature.FromPublicKey(pub)
	if err != nil {
		panic(err)
	}

	// Received envelope
	envelopeRaw := `{"content_type":"types.datadoghq.com/v1/AppInfo","content":"CihiMGE0Y2ZjOWZkMjEyNTJlYWY1ZTIwOTNiNzA4OGQ1MjI4ZWIyYjQ3EgRtYWluGhQyMDIyLTEyLTEyVDEzOjU3OjMyWiIEMS4yMCoGdjEuMC4y","signature":{"version":2,"algorithm":"ed25519","pubkey":"Fx5o8C5vZr+f9lwTx12bK0ksL0DtYeBlB8uLInw5cNU=","timestamp":1670850610,"proof":"sxmBbwylYhmtvtAyIuvPmjNncvJCxBmZeNBD4bnS17avg2nAueHg1hStwrjzErqU5Mr4qpWGKGKH8+dUbhyQBQ=="}}`

	// Try to deocde the envelope
	var envelope Envelope
	if err := json.NewDecoder(bytes.NewReader([]byte(envelopeRaw))).Decode(&envelope); err != nil {
		panic(err)
	}

	// Verify and unwrap the envelope
	payload, err := VerifyAndUnwrap(&envelope, verifier)
	if err != nil {
		panic(err)
	}

	// Output:
	// 00000000  0a 28 62 30 61 34 63 66  63 39 66 64 32 31 32 35  |.(b0a4cfc9fd2125|
	// 00000010  32 65 61 66 35 65 32 30  39 33 62 37 30 38 38 64  |2eaf5e2093b7088d|
	// 00000020  35 32 32 38 65 62 32 62  34 37 12 04 6d 61 69 6e  |5228eb2b47..main|
	// 00000030  1a 14 32 30 32 32 2d 31  32 2d 31 32 54 31 33 3a  |..2022-12-12T13:|
	// 00000040  35 37 3a 33 32 5a 22 04  31 2e 32 30 2a 06 76 31  |57:32Z".1.20*.v1|
	// 00000050  2e 30 2e 32                                       |.0.2|
	fmt.Printf("%s\n", hex.Dump(payload))
}
