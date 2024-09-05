package trustdidweb

import (
	"crypto"
	"crypto/ed25519"
	"testing"

	"github.com/go-json-experiment/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNextKeyHash(t *testing.T) {
	t.Run("verify a nextKeyHash", func(t *testing.T) {
		nextKeyJWK := `{"crv":"Ed25519","kty":"OKP","x":"WBKH7GNqRzMnBJLBx0HZ8rBltvBf4O_KaGmOn7T7-Q8","d":"8WHbfpB9GutxXGPFlgahz-7EjZedliXOtz61fzbzOrg"}`
		nextKeyHash := NextKeyHash(`QmSUEFKzVUqDBVhErbC8aWvdaRFATpiHXqVHg9ZNcsyqPQ`)
		nextPrivKey := parseJWKPrivateKey(t, nextKeyJWK).(ed25519.PrivateKey)
		nextPubKey := nextPrivKey.Public()

		err := nextKeyHash.VerifyPublicKey(nextPubKey)
		assert.NoError(t, err)

		calculatedKeyHash, err := NewNextKeyHash(nextPubKey)
		assert.NoError(t, err)
		assert.Equal(t, nextKeyHash, calculatedKeyHash)
	})
}

func TestEncodePubKey(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pubKey := testVector1.signer(t).Public()
		encodedKey, err := NewUpdateKey(pubKey)
		assert.NoError(t, err)

		entry := LogEntry{}
		err = entry.UnmarshalJSONL([]byte(testVector1.log[0]))
		require.NoError(t, err)
		assert.Equal(t, entry.Params.UpdateKeys[0], encodedKey)
	})
}

func TestNewInitialParams(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		signer, err := NewSigner(CRYPTO_SUITE_EDDSA_JCS_2022)
		require.NoError(t, err)
		pubKeys := []crypto.PublicKey{signer.Public()}

		nextKeyHashes := []NextKeyHash{"hash1", "hash2"}

		params, err := NewInitialParams(pubKeys, nextKeyHashes)
		assert.NoError(t, err)
		assert.Equal(t, TDWMethodv03, params.Method)
		assert.Equal(t, "{SCID}", params.Scid)
		assert.True(t, params.Prerotation, "prerotation should be true")
		assert.Equal(t, 1, len(params.UpdateKeys))
		assert.Equal(t, NextKeyHash("hash1"), params.NextKeyHashes[0])
		assert.Equal(t, NextKeyHash("hash2"), params.NextKeyHashes[1])
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
		params, err := NewInitialParams(pubKeys, []NextKeyHash{})
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
	t.Run("empty params returns an empty JSON object", func(t *testing.T) {
		params := LogParams{}
		data, err := json.Marshal(params)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(data))
	})

	t.Run("an empty updateKeys array must be marshalled but empty", func(t *testing.T) {
		params := LogParams{UpdateKeys: []string{}}
		data, err := json.Marshal(params)
		require.NoError(t, err)
		assert.JSONEq(t, `{"updateKeys":[]}`, string(data))
	})
}

func TestLogParams_UnmarshalJSON(t *testing.T) {
	t.Run("empty JSON object unmarshals to empty params", func(t *testing.T) {
		params := LogParams{}
		err := json.Unmarshal([]byte(`{}`), &params)
		require.NoError(t, err)
		assert.True(t, params.UpdateKeys == nil)
	})

	t.Run("an empty updateKeys array must be defined but empty", func(t *testing.T) {
		params := LogParams{}
		err := json.Unmarshal([]byte(`{"updateKeys":[]}`), &params)
		require.NoError(t, err)
		assert.Empty(t, params.UpdateKeys)
		assert.True(t, len(params.UpdateKeys) == 0)
		assert.False(t, params.UpdateKeys == nil)
	})
}

func TestLogParams_copy(t *testing.T) {
	t.Run("copy returns a deep copy of the params", func(t *testing.T) {
		params := LogParams{
			Method:        "method",
			Scid:          "scid",
			Prerotation:   true,
			UpdateKeys:    []string{"key1", "key2"},
			NextKeyHashes: []NextKeyHash{"hash1", "hash2"},
		}
		paramsCopy := params.copy()
		assert.Equal(t, params, paramsCopy)
		assert.False(t, &params == &paramsCopy)
		assert.False(t, &params.UpdateKeys == &paramsCopy.UpdateKeys)
		assert.False(t, &params.NextKeyHashes == &paramsCopy.NextKeyHashes)
	})
}
