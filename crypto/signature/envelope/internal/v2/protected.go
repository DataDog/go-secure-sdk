package v2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/DataDog/go-secure-sdk/crypto/canonicalization"
	"github.com/DataDog/go-secure-sdk/crypto/signature"
)

const Version = uint8(0x02)

// ComputeProtected is used to assemble the protected content to be signed/verified.
func ComputeProtected(algorithm signature.Algorithm, ts uint64, kid, contentType, payload []byte) ([]byte, error) {
	// Pre-hash payload to prevent too large input to be used
	// SHA256 is vulnerable to length extension attack, we use HMAC-SHA256.
	// It could be exploited via crafted contentType or payload to add arbitrary
	// content to generate the same hash value, allowing the attacker to generate
	// an identic piece which could be used to bypass the signature verification.
	// Due to its different internal construction HMAC is not vulnerable to this
	// attack.
	//
	// More information. http://dtdg.co/skb-data-protection-error-detection-hash-dsig
	//
	// Alternatively SHA3 could be used, but not sufficiently optimized in this
	// current Go version (1.19.5).
	h := hmac.New(sha256.New, []byte("datadog-envelope-content-hash-v1"))

	// Ensure to "compress" the user controllable parameters to a fixed length
	// with HMAC-SHA256.
	// HMAC(contentType || payload)
	h.Write(contentType)
	h.Write(payload)

	// Binds the contentType and payload values together.
	hContent := h.Sum(nil)

	// Encode timestamp
	var tsRaw [8]byte
	binary.LittleEndian.PutUint64(tsRaw[:], ts)

	// Assemble protected specification (156 bytes)
	protected, err := canonicalization.PreAuthenticationEncoding(
		[]byte("datadog-envelope-signature-v2"), // Purpose (Domain separation string)
		[]byte(algorithm),                       // Used algorithm (How)
		kid,                                     // Public key binding (Who)
		tsRaw[:],                                // When
		hContent[:],                             // What
	)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare protected pieces: %w", err)
	}

	return protected, nil
}

// ComputeKeyID is used to generate the key identifier from the serialized
// public key.
func ComputeKeyID(pub []byte) [32]byte {
	return sha256.Sum256(pub)
}
