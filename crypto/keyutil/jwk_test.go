// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package keyutil

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

func TestToJWK(t *testing.T) {
	t.Parallel()

	t.Run("nil key", func(t *testing.T) {
		t.Parallel()

		_, err := ToJWK(nil)
		require.Error(t, err)
	})

	t.Run("ED25519", func(t *testing.T) {
		t.Parallel()

		pub, pk, err := GenerateKeyPairWithRand(randomness.NewLockedRand(1), ED25519)
		require.NoError(t, err)

		pubJWK, err := ToJWK(pub)
		require.NoError(t, err)
		pubRaw, err := json.Marshal(pubJWK)
		require.NoError(t, err)
		require.Equal(t, `{"kty":"OKP","kid":"pLkKHIDVUOtkdhfj6bkmCV29eu61xQOqcwATbfP466c","crv":"Ed25519","x":"bxWBcJu3se8DDSENsY47C6HHdvumXYzarQVBUULRifg"}`, string(pubRaw))

		pkJWK, err := ToJWK(pk)
		require.NoError(t, err)
		pkRaw, err := json.Marshal(pkJWK)
		require.NoError(t, err)
		require.Equal(t, `{"kty":"OKP","kid":"pLkKHIDVUOtkdhfj6bkmCV29eu61xQOqcwATbfP466c","crv":"Ed25519","x":"bxWBcJu3se8DDSENsY47C6HHdvumXYzarQVBUULRifg","d":"Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk"}`, string(pkRaw))
	})

	t.Run("EC", func(t *testing.T) {
		t.Parallel()

		pub, pk, err := GenerateKeyPairWithRand(randomness.NewLockedRand(1), EC)
		require.NoError(t, err)

		pubJWK, err := ToJWK(pub)
		require.NoError(t, err)
		pubRaw, err := json.Marshal(pubJWK)
		require.NoError(t, err)
		require.Equal(t, `{"kty":"EC","kid":"Omv6VHrsh5UADR4iFyPmMoG5796UpOHYJxcHccNr86A","crv":"P-256","x":"vZ1kpJjwsUocZ6eNxfj6zrWxle7DX5G0P5Mc4vRIKNE","y":"kl2JfGSa_8LTlAV10JbtjRmwkIscaiBCxidYkFdRk5U"}`, string(pubRaw))

		pkJWK, err := ToJWK(pk)
		require.NoError(t, err)
		pkRaw, err := json.Marshal(pkJWK)
		require.NoError(t, err)
		require.Equal(t, `{"kty":"EC","kid":"Omv6VHrsh5UADR4iFyPmMoG5796UpOHYJxcHccNr86A","crv":"P-256","x":"vZ1kpJjwsUocZ6eNxfj6zrWxle7DX5G0P5Mc4vRIKNE","y":"kl2JfGSa_8LTlAV10JbtjRmwkIscaiBCxidYkFdRk5U","d":"N8HEXiXhvByrJ1zKSFT6Y2l2KqDWwWzKf-t4CyWrNKc"}`, string(pkRaw))
	})
}

func TestFromJWK(t *testing.T) {
	t.Parallel()

	t.Run("nil reader", func(t *testing.T) {
		t.Parallel()

		_, err := FromJWK(nil)
		require.Error(t, err)
	})

	t.Run("too large content", func(t *testing.T) {
		t.Parallel()

		_, err := FromJWK(randomness.NewReader(1))
		require.Error(t, err)
	})

	t.Run("invalid json", func(t *testing.T) {
		t.Parallel()

		in := strings.NewReader(`{"`)
		out, err := FromJWK(in)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("ED25519", func(t *testing.T) {
		t.Parallel()

		in := strings.NewReader(`{"kty":"OKP","kid":"pLkKHIDVUOtkdhfj6bkmCV29eu61xQOqcwATbfP466c","crv":"Ed25519","x":"bxWBcJu3se8DDSENsY47C6HHdvumXYzarQVBUULRifg","d":"Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk"}`)
		out, err := FromJWK(in)
		require.NoError(t, err)
		require.NotNil(t, out)
		require.Equal(t, "", out.Algorithm)
		require.Equal(t, "pLkKHIDVUOtkdhfj6bkmCV29eu61xQOqcwATbfP466c", out.KeyID)
	})

	t.Run("EC", func(t *testing.T) {
		t.Parallel()

		in := strings.NewReader(`{"kty":"EC","kid":"Omv6VHrsh5UADR4iFyPmMoG5796UpOHYJxcHccNr86A","crv":"P-256","x":"vZ1kpJjwsUocZ6eNxfj6zrWxle7DX5G0P5Mc4vRIKNE","y":"kl2JfGSa_8LTlAV10JbtjRmwkIscaiBCxidYkFdRk5U","d":"N8HEXiXhvByrJ1zKSFT6Y2l2KqDWwWzKf-t4CyWrNKc"}`)
		out, err := FromJWK(in)
		require.NoError(t, err)
		require.NotNil(t, out)
		require.Equal(t, "", out.Algorithm)
		require.Equal(t, "Omv6VHrsh5UADR4iFyPmMoG5796UpOHYJxcHccNr86A", out.KeyID)
	})
}

func TestJWKEncryptionDecryption(t *testing.T) {
	t.Parallel()

	_, pk, err := GenerateKeyPairWithRand(randomness.NewLockedRand(1), ED25519)
	require.NoError(t, err)

	jwk, err := ToJWK(pk)
	require.NoError(t, err)

	// Encrypt the JWK
	jwe, err := ToEncryptedJWK(jwk, []byte("very-secret-password"))
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		// Decrypt
		out, err := FromEncryptedJWK(strings.NewReader(jwe), []byte("very-secret-password"))
		require.NoError(t, err)
		require.Equal(t, pk, out.Key)
	})

	t.Run("invalid secret", func(t *testing.T) {
		t.Parallel()

		out, err := FromEncryptedJWK(strings.NewReader(jwe), []byte("wrong"))
		require.Error(t, err)
		require.Nil(t, out)
	})
}
