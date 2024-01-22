package fpe

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/netip"

	"github.com/DataDog/go-secure-sdk/privacy/encryption/fpe/ff3"
)

// IP uses FF3rev1 from NIST To apply format preserving encryption on the input
// netip.Addr object. By providing an IPv4 you will have a matching and reversible
// IPv4, same for IPv6 adresses.
func IP(key, tweak []byte, ip netip.Addr, operation Operation) (*netip.Addr, error) {
	var ipHex string

	// Initialize a FF3-1 FPE with hexadecimal radix.
	ff3r1, err := ff3.NewFF3_1(key, tweak, "0123456789abcdef")
	if err != nil {
		return nil, fmt.Errorf("unable to initialize the encryption engine: %w", err)
	}

	// Convert the input IP address to ranked hexadecimal integer.
	ipInt := big.NewInt(0)
	switch {
	case ip.Is4():
		ipv4 := ip.As4()
		ipInt.SetBytes(ipv4[:])
		ipHex = hex.EncodeToString(ipInt.Bytes())
	case ip.Is6():
		ipv6 := ip.As16()
		ipInt.SetBytes(ipv6[:])
		ipHex = hex.EncodeToString(ipInt.Bytes())
	default:
		return nil, errors.New("invalid ip address")
	}

	var (
		outHex       string
		errOperation error
	)
	switch operation {
	case Encrypt:
		outHex, errOperation = ff3r1.Encrypt(ipHex, nil)
	case Decrypt:
		outHex, errOperation = ff3r1.Decrypt(ipHex, nil)
	default:
		return nil, fmt.Errorf("unsupported operation")
	}
	if errOperation != nil {
		return nil, fmt.Errorf("unable to successfully apply the requested operation: %w", errOperation)
	}

	// Decode from hex ranked to netip.Addr
	outRaw, err := hex.DecodeString(outHex)
	if err != nil {
		return nil, fmt.Errorf("unable to decode hex output: %w", err)
	}

	// Recreate an IP instance from the decoded rank
	out, valid := netip.AddrFromSlice(outRaw)
	if !valid {
		return nil, errors.New("invalid decoded IP address")
	}

	return &out, nil
}
