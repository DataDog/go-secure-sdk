// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-secure-sdk/crypto/keyutil"
)

func TestProvider_New(t *testing.T) {
	t.Parallel()

	kp := New()
	require.NotNil(t, kp)
}

func TestProvider_Build(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		kp, err := Build()
		require.NoError(t, err)
		require.NotNil(t, kp)
	})

	t.Run("one", func(t *testing.T) {
		t.Parallel()

		kp, err := Build(
			WithEntry("production/http/session/key", RandomSymmetricSecret(32, EncryptionPurpose)),
		)
		require.NoError(t, err)
		require.NotNil(t, kp)

		// Resolve valid key with patching purpose
		s1, err := kp.GetSymmetricFor("production/http/session/key", EncryptionPurpose)
		require.NoError(t, err)
		require.NotNil(t, s1)

		// Resolve invalid key
		s2, err := kp.GetSymmetricFor("production/server/database/pii", EncryptionPurpose)
		require.ErrorIs(t, err, ErrKeyNotFound)
		require.Nil(t, s2)
	})
}

func Test_defaultProvider_GetSymmetricFor(t *testing.T) {
	t.Parallel()

	kp, err := Build(
		WithEntry("testing/symmetric/encryption", RandomSymmetricSecret(32, EncryptionPurpose)),
	)
	require.NoError(t, err)

	t.Run("not existent", func(t *testing.T) {
		t.Parallel()

		k, err := kp.GetSymmetricFor("testing/symmetric/not-existent", SignaturePurpose)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("purpose mismatch", func(t *testing.T) {
		t.Parallel()

		k, err := kp.GetSymmetricFor("testing/symmetric/encryption", SignaturePurpose)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		k, err := kp.GetSymmetricFor("testing/symmetric/encryption", EncryptionPurpose)
		require.NoError(t, err)
		require.NotNil(t, k)
	})
}

func Test_defaultProvider_GetPrivateFor(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kp, err := Build(
		WithEntry("testing/private/encryption", StaticPrivateKey(priv, EncryptionPurpose)),
	)
	require.NoError(t, err)

	t.Run("not existent", func(t *testing.T) {
		t.Parallel()

		k, err := kp.GetPrivateFor("testing/private/not-existent", SignaturePurpose)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("purpose mismatch", func(t *testing.T) {
		t.Parallel()

		k, err := kp.GetPrivateFor("testing/private/encryption", SignaturePurpose)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		k, err := kp.GetPrivateFor("testing/private/encryption", EncryptionPurpose)
		require.NoError(t, err)
		require.NotNil(t, k)
	})
}

func Test_defaultProvider_GetPublicFor(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kp, err := Build(
		WithEntry("testing/public/encryption", StaticPublicKey(pub)),
	)
	require.NoError(t, err)

	t.Run("not existent", func(t *testing.T) {
		t.Parallel()

		k, err := kp.GetPublic("testing/public/not-existent")
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		k, err := kp.GetPublic("testing/public/encryption")
		require.NoError(t, err)
		require.NotNil(t, k)
	})
}

func Test_defaultProvider_GenerateKeyPair(t *testing.T) {
	t.Parallel()

	kp := New()

	t.Run("purposes conflict", func(t *testing.T) {
		t.Parallel()

		k, err := kp.GenerateKeyPair(keyutil.EC, SignaturePurpose, EncryptionPurpose)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		k, err := kp.GenerateKeyPair(keyutil.EC, SignaturePurpose, ExportableKey)
		require.NoError(t, err)
		require.NotNil(t, k)

		pub, err := kp.GetPublic(k.Alias())
		require.NoError(t, err)
		require.NotNil(t, pub)

		priv, err := kp.GetPrivateFor(k.Alias(), SignaturePurpose)
		require.NoError(t, err)
		require.NotNil(t, priv)

		_, err = kp.GetSymmetricFor(k.Alias(), EncryptionPurpose)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyNotFound)
	})
}

func Test_defaultProvider_GenerateSecret(t *testing.T) {
	t.Parallel()

	t.Run("too small", func(t *testing.T) {
		t.Parallel()

		kp := New()
		k, err := kp.GenerateSecret(minSecretLength-1, SignaturePurpose, EncryptionPurpose)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("too large", func(t *testing.T) {
		t.Parallel()

		kp := New()
		k, err := kp.GenerateSecret(maxSecretLength+1, SignaturePurpose, EncryptionPurpose)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("purposes conflict", func(t *testing.T) {
		t.Parallel()

		kp := New()
		k, err := kp.GenerateSecret(32, SignaturePurpose, EncryptionPurpose)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		kp := New()
		k, err := kp.GenerateSecret(32, SignaturePurpose, ExportableKey)
		require.NoError(t, err)
		require.NotNil(t, k)

		sk, err := kp.GetSymmetricFor(k.Alias(), SignaturePurpose)
		require.NoError(t, err)
		require.NotNil(t, sk)

		pub, err := kp.GetPublic(k.Alias())
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyNotFound)
		require.Nil(t, pub)

		priv, err := kp.GetPrivateFor(k.Alias(), SignaturePurpose)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyNotFound)
		require.Nil(t, priv)
	})
}

var _ Key = (*customKey)(nil)

type customKey struct{}

func (customKey) Alias() KeyAlias     { return "" }
func (customKey) Can(KeyPurpose) bool { return false }

func Test_defaultProvider_Register(t *testing.T) {
	t.Parallel()

	t.Run("blank alias", func(t *testing.T) {
		t.Parallel()

		kp := New()
		err := kp.Register("", RandomSymmetricSecret(32, SignaturePurpose))
		require.Error(t, err)
	})

	t.Run("nil factory", func(t *testing.T) {
		t.Parallel()

		kp := New()
		err := kp.Register("production/http/session", nil)
		require.Error(t, err)
	})

	t.Run("factory error", func(t *testing.T) {
		t.Parallel()

		kp := New()
		err := kp.Register("production/http/session", func(alias KeyAlias) (Key, error) {
			return nil, errors.New("test")
		})
		require.Error(t, err)
	})

	t.Run("factory nil key", func(t *testing.T) {
		t.Parallel()

		kp := New()
		err := kp.Register("production/http/session", func(alias KeyAlias) (Key, error) {
			return nil, nil
		})
		require.Error(t, err)
	})

	t.Run("factory unsupported key", func(t *testing.T) {
		t.Parallel()

		kp := New()
		err := kp.Register("production/http/session", func(alias KeyAlias) (Key, error) {
			return &customKey{}, nil
		})
		require.Error(t, err)
	})

	t.Run("duplicate", func(t *testing.T) {
		t.Parallel()

		kp := New()

		err := kp.Register("production/http/session", RandomSymmetricSecret(32, SignaturePurpose))
		require.NoError(t, err)

		err = kp.Register("production/http/session", RandomSymmetricSecret(32, SignaturePurpose))
		require.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		kp := New()

		err := kp.Register("production/http/session", RandomSymmetricSecret(32, SignaturePurpose))
		require.NoError(t, err)

		sk, err := kp.GetSymmetricFor("production/http/session", SignaturePurpose)
		require.NoError(t, err)
		require.NotNil(t, sk)
	})
}

func Test_defaultProvider_Remove(t *testing.T) {
	t.Parallel()

	t.Run("blank alias", func(t *testing.T) {
		t.Parallel()

		kp := New()
		err := kp.Remove("")
		require.Error(t, err)
	})

	t.Run("public", func(t *testing.T) {
		t.Parallel()

		kp := New()

		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = kp.Register("production/http/session", StaticPublicKey(pub))
		require.NoError(t, err)

		sk, err := kp.GetPublic("production/http/session")
		require.NoError(t, err)
		require.NotNil(t, sk)

		err = kp.Remove("production/http/session")
		require.NoError(t, err)

		sk, err = kp.GetPublic("production/http/session")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyNotFound)
		require.Nil(t, sk)
	})

	t.Run("private", func(t *testing.T) {
		t.Parallel()

		kp := New()

		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = kp.Register("production/http/session", StaticPrivateKey(priv, SignaturePurpose))
		require.NoError(t, err)

		sk, err := kp.GetPrivateFor("production/http/session", SignaturePurpose)
		require.NoError(t, err)
		require.NotNil(t, sk)

		err = kp.Remove("production/http/session")
		require.NoError(t, err)

		sk, err = kp.GetPrivateFor("production/http/session", SignaturePurpose)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyNotFound)
		require.Nil(t, sk)
	})

	t.Run("symmetric", func(t *testing.T) {
		t.Parallel()

		kp := New()

		err := kp.Register("production/http/session", RandomSymmetricSecret(32, SignaturePurpose))
		require.NoError(t, err)

		sk, err := kp.GetSymmetricFor("production/http/session", SignaturePurpose)
		require.NoError(t, err)
		require.NotNil(t, sk)

		err = kp.Remove("production/http/session")
		require.NoError(t, err)
	})
}
