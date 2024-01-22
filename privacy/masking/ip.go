package masking

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Reference(s):
// * https://support.google.com/analytics/answer/2763052
// * https://en.internet.nl/privacy/
var (
	IPv4MaskRecommended = 16
	IPv6MaskRecommended = 80
)

// IP will mask the given IP address string according to its detected version.
// The value is parsed to detect the IP address version.
//
// If the format is already known, consider using the direct IPv4/IPv6 function
// which are designed for performance.
func IP(value string) (string, error) {
	// Parse input ip address
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return "", fmt.Errorf("unable to parse input as a value IP address: %w", err)
	}

	// Delegate to mask
	return IPAddr(ip)
}

// IPv4 assumes the given value to be a string representation of an IPv4 address
// and process the string to generate the masked value.
func IPv4(value string) (string, error) {
	s := strings.SplitN(value, ".", 4)
	if len(s) != 4 {
		return "", errors.New("invalid IPv4 address")
	}

	return strings.Join([]string{s[0], s[1], "0", "0"}, "."), nil
}

// IPAddr used the given netip.Addr instance to compute the masked IP address string.
// For IPv4, last 16bits are erased. For IPv6, last 80 bits are erased.
func IPAddr(ip netip.Addr) (string, error) {
	switch {
	case ip.Is4():
		return IPMask(ip, IPv4MaskRecommended)
	case ip.Is6():
		return IPMask(ip, IPv6MaskRecommended)
	default:
		return "", errors.New("the IP address has an unsupported version")
	}
}

// IPMask is used to compute the prefix of the given IP address and erase last
// `mask` bits.
func IPMask(ip netip.Addr, mask int) (string, error) {
	// Compute prefix according to provided mask
	prefix, err := ip.Prefix(ip.BitLen() - mask)
	if err != nil {
		return "", fmt.Errorf("unable to compute IP address prefix: %w", err)
	}

	// The string prepresentation of the prefix is the anonymized IP address.
	return prefix.Addr().String(), nil
}
