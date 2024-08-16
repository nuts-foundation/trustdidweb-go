package trustdidweb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProorVerify(t *testing.T) {
	t.Run("ok - first entry", func(t *testing.T) {
		entry := LogEntry{}
		err := entry.UnmarshalJSONL([]byte(testVector1.log[0]))
		require.NoError(t, err)

		proof := entry.Proof[0]

		doc, err := DIDLog{entry}.Document()
		require.NoError(t, err)

		err = proof.Verify(entry.VersionId.String(), entry.Params.UpdateKeys, doc)
		assert.NoError(t, err)
	})

	t.Run("nok - challenge mismatch", func(t *testing.T) {
		entry := LogEntry{}
		err := entry.UnmarshalJSONL([]byte(testVector1.log[0]))
		require.NoError(t, err)

		proof := entry.Proof[0]

		err = proof.Verify("wrong challenge", entry.Params.UpdateKeys, nil)
		assert.EqualError(t, err, "challenge mismatch")
	})

	t.Run("nok - proof must be signed with the update key from the previous log entry", func(t *testing.T) {
		entry := LogEntry{}
		err := entry.UnmarshalJSONL([]byte(testVector1.log[0]))
		require.NoError(t, err)

		proof := entry.Proof[0]
		proof.VerificationMethod = "did:key:foo#foo"

		err = proof.Verify(entry.VersionId.String(), entry.Params.UpdateKeys, nil)
		assert.EqualError(t, err, "proof must be signed with an active update key")
	})

	t.Run("nok - unsupported proof type", func(t *testing.T) {
		entry := LogEntry{}
		err := entry.UnmarshalJSONL([]byte(testVector1.log[0]))
		require.NoError(t, err)

		proof := entry.Proof[0]
		proof.Type = "unsupported"

		err = proof.Verify(entry.VersionId.String(), entry.Params.UpdateKeys, nil)
		assert.EqualError(t, err, "unsupported proof type: unsupported")
	})

	t.Run("nok - unsupported proof purpose", func(t *testing.T) {
		entry := LogEntry{}
		err := entry.UnmarshalJSONL([]byte(testVector1.log[0]))
		require.NoError(t, err)

		proof := entry.Proof[0]
		proof.ProofPurpose = "unsupported"

		err = proof.Verify(entry.VersionId.String(), entry.Params.UpdateKeys, nil)
		assert.EqualError(t, err, "unsupported proof purpose: unsupported")
	})

	t.Run("nok - incompatible cryptosuite and key type", func(t *testing.T) {
		t.Run("suite ecdsa-jcs-2019 wont work with ed25519-pub", func(t *testing.T) {
			entry := LogEntry{}
			err := entry.UnmarshalJSONL([]byte(testVector1.log[0]))
			require.NoError(t, err)

			proof := entry.Proof[0]
			proof.Cryptosuite = CRYPTO_SUITE_ECDSA_JCS_2019

			err = proof.Verify(entry.VersionId.String(), entry.Params.UpdateKeys, nil)
			assert.EqualError(t, err, "incompatible key type 'ed25519-pub' for cryptosuite 'ecdsa-jcs-2019'")
		})

		t.Run("suite eddsa-jcs-2022 wont work with p384-pub", func(t *testing.T) {
			entry := LogEntry{}
			err := entry.UnmarshalJSONL([]byte(testVector1.log[0]))
			require.NoError(t, err)

			proof := entry.Proof[0]
			proof.VerificationMethod = "did:key:z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc#z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc"

			err = proof.Verify(entry.VersionId.String(), []string{"z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc"}, nil)
			assert.EqualError(t, err, "incompatible key type 'p384-pub' for cryptosuite 'eddsa-jcs-2022'")
		})

		t.Run("nok - unsupported crytosuite", func(t *testing.T) {
			entry := LogEntry{}
			err := entry.UnmarshalJSONL([]byte(testVector1.log[0]))
			require.NoError(t, err)

			proof := entry.Proof[0]
			proof.Cryptosuite = "unsupported"

			err = proof.Verify(entry.VersionId.String(), entry.Params.UpdateKeys, nil)
			assert.EqualError(t, err, "unsupported cryptosuite: unsupported")
		})
	})

	t.Run("nok - invalid signature", func(t *testing.T) {
		entry := LogEntry{}
		err := entry.UnmarshalJSONL([]byte(testVector1.log[0]))
		require.NoError(t, err)

		proof := entry.Proof[0]
		// change the created date to make the signature invalid
		proof.Created = "2022-01-01T00:00:00Z"

		doc, err := DIDLog{entry}.Document()
		require.NoError(t, err)

		err = proof.Verify(entry.VersionId.String(), entry.Params.UpdateKeys, doc)
		assert.EqualError(t, err, "invalid signature")
	})
}
