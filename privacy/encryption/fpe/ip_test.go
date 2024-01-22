package fpe

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIP(t *testing.T) {
	t.Parallel()

	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("D9C9D9BF96A6A53825BA8117BBD55099")
	if err != nil {
		panic(err)
	}
	tweak, err := hex.DecodeString("F9924954C8EBC1")
	if err != nil {
		panic(err)
	}

	t.Run("invalid tweak", func(t *testing.T) {
		t.Parallel()

		_, err := IP(key, []byte{}, netip.Addr{}, Encrypt)
		assert.Error(t, err)
	})

	t.Run("invalid ip address", func(t *testing.T) {
		t.Parallel()

		_, err := IP(key, tweak, netip.Addr{}, Encrypt)
		assert.Error(t, err)
	})

	t.Run("unknown operation", func(t *testing.T) {
		t.Parallel()

		ip, err := netip.ParseAddr("0.0.0.0")
		assert.NoError(t, err)
		assert.NotNil(t, ip)

		_, err = IP(key, tweak, ip, 8)
		assert.Error(t, err)
	})

	t.Run("IPv4", func(t *testing.T) {
		t.Parallel()

		realIp := "8.8.8.8"
		anonymizedIp := "73.200.56.91"

		t.Run("Encrypt", func(t *testing.T) {
			t.Parallel()

			ip, err := netip.ParseAddr(realIp)
			assert.NoError(t, err)
			assert.NotNil(t, ip)

			out, err := IP(key, tweak, ip, Encrypt)
			assert.NoError(t, err)
			assert.Equal(t, anonymizedIp, out.String())
		})

		t.Run("Decrypt", func(t *testing.T) {
			t.Parallel()

			ip, err := netip.ParseAddr(anonymizedIp)
			assert.NoError(t, err)
			assert.NotNil(t, ip)

			out, err := IP(key, tweak, ip, Decrypt)
			assert.NoError(t, err)
			assert.Equal(t, realIp, out.String())
		})
	})

	t.Run("IPv6", func(t *testing.T) {
		t.Parallel()

		realIp := "2001:4860:4860::8888"
		anonymizedIp := "fa44:a029:d85f:e4e3:6183:9d59:3857:a016"

		t.Run("Encrypt", func(t *testing.T) {
			t.Parallel()

			ip, err := netip.ParseAddr(realIp)
			assert.NoError(t, err)
			assert.NotNil(t, ip)

			out, err := IP(key, tweak, ip, Encrypt)
			assert.NoError(t, err)
			assert.Equal(t, anonymizedIp, out.String())
		})

		t.Run("Decrypt", func(t *testing.T) {
			t.Parallel()

			ip, err := netip.ParseAddr(anonymizedIp)
			assert.NoError(t, err)
			assert.NotNil(t, ip)

			out, err := IP(key, tweak, ip, Decrypt)
			assert.NoError(t, err)
			assert.Equal(t, realIp, out.String())
		})
	})
}
