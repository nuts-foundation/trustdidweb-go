package trustdidweb

import (
	"crypto"
	"testing"

	"github.com/go-json-experiment/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInitialParams(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		signer, err := NewSigner(CRYPTO_SUITE_EDDSA_JCS_2022)
		require.NoError(t, err)
		pubKeys := []crypto.PublicKey{signer.Public()}

		nextKeyHashes := []string{"hash1", "hash2"}

		params, err := NewInitialParams(pubKeys, nextKeyHashes)
		assert.NoError(t, err)
		assert.Equal(t, TDWMethodv03, params.Method)
		assert.Equal(t, "{SCID}", params.Scid)
		assert.True(t, params.Prerotation, "prerotation should be true")
		assert.Empty(t, params.Cryptosuite, "for the eddsa-jcs-2022, crypto suite is not set")
		assert.Equal(t, 1, len(params.UpdateKeys))
		assert.Equal(t, "hash1", params.NextKeyHashes[0])
		assert.Equal(t, "hash2", params.NextKeyHashes[1])
	})

	t.Run("ok - edsa-jcs-2019 should set the cryptosuite", func(t *testing.T) {
		signer, err := NewSigner(CRYPTO_SUITE_ECDSA_JCS_2019)
		require.NoError(t, err)
		pubKeys := []crypto.PublicKey{signer.Public()}
		params, err := NewInitialParams(pubKeys, nil)
		assert.NoError(t, err)
		assert.Equal(t, CRYPTO_SUITE_ECDSA_JCS_2019, params.Cryptosuite)
	})

	t.Run("ok - multiple public key types", func(t *testing.T) {
		signer1, err := NewSigner(CRYPTO_SUITE_EDDSA_JCS_2022)
		require.NoError(t, err)
		signer2, err := NewSigner(CRYPTO_SUITE_EDDSA_JCS_2022)
		require.NoError(t, err)
		pubKeys := []crypto.PublicKey{signer1.Public(), signer2.Public()}
		params, err := NewInitialParams(pubKeys, nil)
		assert.NoError(t, err)
		assert.Len(t, params.UpdateKeys, 2)
	})

	t.Run("ok - empty nextKeyHashes", func(t *testing.T) {
		signer, err := NewSigner(CRYPTO_SUITE_EDDSA_JCS_2022)
		require.NoError(t, err)
		pubKeys := []crypto.PublicKey{signer.Public()}
		params, err := NewInitialParams(pubKeys, []string{})
		assert.NoError(t, err)
		assert.False(t, params.Prerotation, "prerotation should be false")
		assert.Empty(t, params.NextKeyHashes)
	})

	t.Run("nok - mixed crypto suites", func(t *testing.T) {
		signer1, err := NewSigner(CRYPTO_SUITE_EDDSA_JCS_2022)
		require.NoError(t, err)
		signer2, err := NewSigner(CRYPTO_SUITE_ECDSA_JCS_2019)
		require.NoError(t, err)
		pubKeys := []crypto.PublicKey{signer1.Public(), signer2.Public()}
		_, err = NewInitialParams(pubKeys, nil)
		assert.EqualError(t, err, "multiple public key types not supported")
	})

	t.Run("nok - unsupported public key type", func(t *testing.T) {
		pubKeys := []crypto.PublicKey{nil}
		_, err := NewInitialParams(pubKeys, nil)
		assert.EqualError(t, err, "unsupported public key type: <nil>")
	})

	t.Run("nok - missing update keys", func(t *testing.T) {
		_, err := NewInitialParams([]crypto.PublicKey{}, nil)
		assert.EqualError(t, err, "at least one public key is required")
	})
}

func TestLogParams_MarshalJSON(t *testing.T) {
	t.Run("empty params", func(t *testing.T) {
		params := LogParams{}
		data, err := json.Marshal(params)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(data))
	})
}
