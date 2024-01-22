package masking

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPMask_Error(t *testing.T) {
	t.Parallel()

	ip4, err := netip.ParseAddr("88.22.34.1")
	require.NoError(t, err)

	maskedIP, err := IPMask(ip4, 33)
	require.Error(t, err)
	require.Empty(t, maskedIP)
}

func TestIPAddr_Invalid(t *testing.T) {
	t.Parallel()

	maskedIP, err := IPAddr(netip.Addr{})
	require.Error(t, err)
	require.Empty(t, maskedIP)
}

func TestIPAddr_IPv4(t *testing.T) {
	t.Parallel()

	ip4, err := netip.ParseAddr("88.22.34.1")
	require.NoError(t, err)

	maskedIP, err := IPAddr(ip4)
	require.NoError(t, err)
	require.Equal(t, "88.22.0.0", maskedIP)
}

func TestIPAddr_IPv6(t *testing.T) {
	t.Parallel()

	ip4, err := netip.ParseAddr("2a00:b6e0:0001:0200:0177:0000:0000:0001")
	require.NoError(t, err)

	maskedIP, err := IPAddr(ip4)
	require.NoError(t, err)
	require.Equal(t, "2a00:b6e0:1::", maskedIP)
}

func TestIP_Invalid(t *testing.T) {
	t.Parallel()

	maskedIP, err := IP("81")
	require.Error(t, err)
	require.Empty(t, maskedIP)
}

func TestIP_IPv4(t *testing.T) {
	t.Parallel()

	maskedIP, err := IP("88.22.34.1")
	require.NoError(t, err)
	require.Equal(t, "88.22.0.0", maskedIP)
}

func TestIP_IPv6(t *testing.T) {
	t.Parallel()

	maskedIP, err := IP("2a00:b6e0:0001:0200:0177:0000:0000:0001")
	require.NoError(t, err)
	require.Equal(t, "2a00:b6e0:1::", maskedIP)
}

func TestIPv4_Invalid(t *testing.T) {
	t.Parallel()

	maskedIP, err := IPv4("88")
	require.Error(t, err)
	require.Empty(t, maskedIP)
}
