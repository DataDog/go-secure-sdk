// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package encryption

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
	t.Parallel()

	keys := [][]byte{
		[]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
		[]byte("RWZLutMaZj6ea3Bf6FqGVoFquuE5jqyN"),
		[]byte("ATCkaljMhYokvN08nZMX358JwPGY4DY0"),
		[]byte("zzTPjjOhqexyMKXAxbelXOZI2lW7VM79kQXEWRPkvMnaWzlJbN1prxEk02huCpD1"),
	}

	t.Run("empty keys", func(t *testing.T) {
		t.Parallel()

		plaintext, err := Open(nil, nil)
		require.Error(t, err)
		require.Nil(t, plaintext)
	})

	t.Run("ciphertext too short", func(t *testing.T) {
		t.Parallel()

		plaintext, err := Open(keys, nil)
		require.Error(t, err)
		require.Nil(t, plaintext)
	})

	t.Run("Key not found", func(t *testing.T) {
		t.Parallel()

		t.Run("FIPS", func(t *testing.T) {
			t.Parallel()

			otherKey := []byte("YTZWeCvYsIJQFELf0KLAX6DzMBUVzhsD")
			otherEncryption, err := ValueWithMode(FIPS, otherKey)
			require.NoError(t, err)
			require.NotNil(t, otherEncryption)

			msg := []byte("Hello World!")

			ciphertext, err := otherEncryption.Seal(msg)
			require.NoError(t, err)

			plaintext, err := Open(keys, ciphertext)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrNoMatchingKey)
			require.Nil(t, plaintext)
		})

		t.Run("Modern", func(t *testing.T) {
			t.Parallel()

			otherKey := []byte("YTZWeCvYsIJQFELf0KLAX6DzMBUVzhsD")
			otherEncryption, err := ValueWithMode(Modern, otherKey)
			require.NoError(t, err)
			require.NotNil(t, otherEncryption)

			msg := []byte("Hello World!")

			ciphertext, err := otherEncryption.Seal(msg)
			require.NoError(t, err)

			plaintext, err := Open(keys, ciphertext)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrNoMatchingKey)
			require.Nil(t, plaintext)
		})

		t.Run("Convergent", func(t *testing.T) {
			t.Parallel()

			otherKey := []byte("QXEWRPkvMnaWzlJbN1prxEk02huCpD1zzTPjjOhqexyMKXAxbelXOZI2lW7VM79k")
			otherEncryption, err := Convergent(otherKey)
			require.NoError(t, err)
			require.NotNil(t, otherEncryption)

			msg := []byte("Hello World!")

			ciphertext, err := otherEncryption.Seal(msg)
			require.NoError(t, err)

			plaintext, err := Open(keys, ciphertext)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrNoMatchingKey)
			require.Nil(t, plaintext)
		})
	})

	t.Run("Valid", func(t *testing.T) {
		t.Parallel()

		t.Run("FIPS", func(t *testing.T) {
			t.Parallel()

			otherEncryption, err := ValueWithMode(FIPS, keys[2])
			require.NoError(t, err)
			require.NotNil(t, otherEncryption)

			msg := []byte("Hello World!")

			ciphertext, err := otherEncryption.Seal(msg)
			require.NoError(t, err)

			plaintext, err := Open(keys, ciphertext)
			require.NoError(t, err)
			require.Equal(t, msg, plaintext)
		})

		t.Run("Modern", func(t *testing.T) {
			t.Parallel()

			otherEncryption, err := ValueWithMode(Modern, keys[2])
			require.NoError(t, err)
			require.NotNil(t, otherEncryption)

			msg := []byte("Hello World!")

			ciphertext, err := otherEncryption.Seal(msg)
			require.NoError(t, err)

			plaintext, err := Open(keys, ciphertext)
			require.NoError(t, err)
			require.Equal(t, msg, plaintext)
		})

		t.Run("Convergent", func(t *testing.T) {
			t.Parallel()

			otherEncryption, err := Convergent(keys[3])
			require.NoError(t, err)
			require.NotNil(t, otherEncryption)

			msg := []byte("Hello World!")

			ciphertext, err := otherEncryption.Seal(msg)
			require.NoError(t, err)

			plaintext, err := Open(keys, ciphertext)
			require.NoError(t, err)
			require.Equal(t, msg, plaintext)
		})
	})
}

func TestRotate(t *testing.T) {
	t.Parallel()

	keys := [][]byte{
		[]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
		[]byte("RWZLutMaZj6ea3Bf6FqGVoFquuE5jqyN"),
		[]byte("ATCkaljMhYokvN08nZMX358JwPGY4DY0"),
		[]byte("zzTPjjOhqexyMKXAxbelXOZI2lW7VM79kQXEWRPkvMnaWzlJbN1prxEk02huCpD1"),
		[]byte("ebgcMo6HmztZNOETdmVsAuF9plukVGPMl1AKzkG2VSF07D5Qdk5w5fbZ323Tg6Es"),
	}

	t.Run("empty keys", func(t *testing.T) {
		t.Parallel()

		plaintext, err := RotateKey(nil, nil, nil)
		require.Error(t, err)
		require.Nil(t, plaintext)
	})

	t.Run("ciphertext too short", func(t *testing.T) {
		t.Parallel()

		plaintext, err := RotateKey(keys, nil, nil)
		require.Error(t, err)
		require.Nil(t, plaintext)
	})

	t.Run("Open error", func(t *testing.T) {
		t.Parallel()

		otherKey := []byte("YTZWeCvYsIJQFELf0KLAX6DzMBUVzhsD")
		otherEncryption, err := Value(otherKey)
		require.NoError(t, err)
		require.NotNil(t, otherEncryption)

		msg := []byte("Hello World!")

		ciphertext, err := otherEncryption.Seal(msg)
		require.NoError(t, err)

		plaintext, err := RotateKey(keys, keys[1], ciphertext)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoMatchingKey)
		require.Nil(t, plaintext)
	})

	t.Run("key error", func(t *testing.T) {
		t.Parallel()

		otherKey := []byte("YTZWeCvYsIJQFELf0KLAX6DzMBUVzhsD")
		otherEncryption, err := Value(otherKey)
		require.NoError(t, err)
		require.NotNil(t, otherEncryption)

		msg := []byte("Hello World!")

		ciphertext, err := otherEncryption.Seal(msg)
		require.NoError(t, err)

		plaintext, err := RotateKey(keys, []byte(""), ciphertext)
		require.Error(t, err)
		require.Nil(t, plaintext)
	})

	t.Run("Valid", func(t *testing.T) {
		t.Parallel()

		t.Run("FIPS", func(t *testing.T) {
			t.Parallel()

			otherEncryption, err := ValueWithMode(FIPS, keys[0])
			require.NoError(t, err)
			require.NotNil(t, otherEncryption)

			msg := []byte("Hello World!")

			ciphertext, err := otherEncryption.Seal(msg)
			require.NoError(t, err)

			newciphertext, err := RotateKey(keys, keys[1], ciphertext)
			require.NoError(t, err)

			plaintext, err := Open(keys, newciphertext)
			require.NoError(t, err)
			require.Equal(t, msg, plaintext)
		})

		t.Run("Modern", func(t *testing.T) {
			t.Parallel()

			otherEncryption, err := ValueWithMode(Modern, keys[0])
			require.NoError(t, err)
			require.NotNil(t, otherEncryption)

			msg := []byte("Hello World!")

			ciphertext, err := otherEncryption.Seal(msg)
			require.NoError(t, err)

			newciphertext, err := RotateKey(keys, keys[1], ciphertext)
			require.NoError(t, err)

			plaintext, err := Open(keys, newciphertext)
			require.NoError(t, err)
			require.Equal(t, msg, plaintext)
		})

		t.Run("Convergent", func(t *testing.T) {
			t.Parallel()

			otherEncryption, err := Convergent(keys[3])
			require.NoError(t, err)
			require.NotNil(t, otherEncryption)

			msg := []byte("Hello World!")

			ciphertext, err := otherEncryption.Seal(msg)
			require.NoError(t, err)

			newciphertext, err := RotateKey(keys, keys[4], ciphertext)
			require.NoError(t, err)

			plaintext, err := Open(keys, newciphertext)
			require.NoError(t, err)
			require.Equal(t, msg, plaintext)
		})
	})
}
