package trustdidweb

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/go-json-experiment/json/jsontext"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/multiformats/go-multicodec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderPathTemplate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pathTemplate := "did:tdw:example.com:dids:{SCID}"
		scid := "123456789abcdefghi"
		path := renderPathTemplate(pathTemplate, scid)
		assert.Equal(t, "did:tdw:example.com:dids:123456789abcdefghi", path)
	})
}

// const priv_key = "9MfszFIPn52i1lOlUvPI_yG077a9vY8leEmJ61aDJf4D3LwT49EG1Mi3hWr7riVv"
const priv_key = "XfWwd4e0TfIQq4t53mpf0Ut7-KeQM3jB4mJKgeU40a2mn8zN0c-ldzgfu5AOcIFw"
const pub_key = "AoVvb94bIG23mP5JuVBHV8KW5b1f95aTDDpXtYqT-LlrCx9xKPgh02d3WNjbkOHNJw"
const jwt_key = `{"crv":"P-384","kty":"EC","x":"hW9v3hsgbbeY_km5UEdXwpblvV_3lpMMOle1ipP4uWsLH3Eo-CHTZ3dY2NuQ4c0n","y":"n0ahfQKvYV18HkFQrEN6DS-bC4r4zAWFsjFol3f61c5wiTooeifBpyGoNfrggDs2","d":"XfWwd4e0TfIQq4t53mpf0Ut7-KeQM3jB4mJKgeU40a2mn8zN0c-ldzgfu5AOcIFw"}'
`

type testVector struct {
	pathTemplate string
	scid         string
	privKeyJWK   string
	log          []string
}

func (v testVector) signer(t *testing.T) crypto.Signer {
	t.Helper()
	privKey, err := jwk.ParseKey([]byte(v.privKeyJWK))
	require.NoError(t, err)
	assert.NotNil(t, privKey)

	var rawKey interface{}
	err = privKey.Raw(&rawKey)
	require.NoError(t, err)

	switch k := rawKey.(type) {
	case ecdsa.PrivateKey:
		return &k
	case ed25519.PrivateKey:
		return &k
	default:
		t.Errorf("unexpected type: %T", k)
		return nil
	}
}

// testVector1 is a vector generated by the trustdidweb-py lib with an ed25519 key.
var testVector1 = testVector{
	pathTemplate: "did:tdw:{SCID}:domain.example",
	scid:         `QmWVViSSXMBoSFskwXV1UtNDtZAdQ41ifyuTeXGNfZnHnA`,
	privKeyJWK:   `{"crv":"Ed25519","kty":"OKP","x":"b1fB2zBKjMOMJfxa3TPAh-EAC7fIHkY5neAdLwd0vx4","d":"6flYopOwxrG9LRkKHBVS8QlUIYWjGY_1TbtKnjL1l7s"}`,
	log: []string{`["1-QmUCAjwkW9KW943FkS7KJ7Dw8bFs2HMNZeddjZpxtyeLaR", "2024-08-15T12:54:34Z", {"prerotation": true, "updateKeys": ["z6MkmwtuuD9jS9DBW4AovTLC4hMbQghBj2NCCCX3NVdAMgTF"], "nextKeyHashes": ["QmVzjCMHvC4Ws6EW2DNrvwCbA3snXdPNNyhFYNSA9VPRwu"], "method": "did:tdw:0.3", "scid": "QmWVViSSXMBoSFskwXV1UtNDtZAdQ41ifyuTeXGNfZnHnA"}, {"value": {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], "id": "did:tdw:QmWVViSSXMBoSFskwXV1UtNDtZAdQ41ifyuTeXGNfZnHnA:domain.example"}}, [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkmwtuuD9jS9DBW4AovTLC4hMbQghBj2NCCCX3NVdAMgTF#z6MkmwtuuD9jS9DBW4AovTLC4hMbQghBj2NCCCX3NVdAMgTF", "created": "2024-08-15T12:54:34Z", "proofPurpose": "authentication", "challenge": "1-QmUCAjwkW9KW943FkS7KJ7Dw8bFs2HMNZeddjZpxtyeLaR", "proofValue": "z4vxR5WsxwF7fWM7WXFVzSqFthaT3kfLj4wJAjKzkuwrETD2Kcz6qMtQZ763zBVh3vUjWSa9Vv2RoDawHyi2nA28q"}]]`,
		`["2-QmbU2qEyKoK74YV3b1QhjFvZanyhXwA7kXtt1LQXk797fp", "2024-08-15T12:54:35Z", {"updateKeys": ["z6Mkq5nYNMjNonx9fRwvuUF4cTV3Jc9r524JVCEEJ9ZnpMh3"], "nextKeyHashes": ["QmXmEjbyKqFdkqgDpUCRrCJiY7bKVw2rEoXUMuYG3srbzs"]}, {"value": {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], "id": "did:tdw:QmWVViSSXMBoSFskwXV1UtNDtZAdQ41ifyuTeXGNfZnHnA:domain.example"}}, [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkmwtuuD9jS9DBW4AovTLC4hMbQghBj2NCCCX3NVdAMgTF#z6MkmwtuuD9jS9DBW4AovTLC4hMbQghBj2NCCCX3NVdAMgTF", "created": "2024-08-15T12:54:35Z", "proofPurpose": "authentication", "challenge": "2-QmbU2qEyKoK74YV3b1QhjFvZanyhXwA7kXtt1LQXk797fp", "proofValue": "z3R9rRrDkMrQPUma1DH9MDtG9HTZEGRJ6YUij5LXsnhStqrgnMAnX1r9GyekuDgG62vxcWBvCvbYCVmhiVLtvPoF7"}]]`,
		`["3-QmagjH7LNdeXk3rEtJStbG8yBLVZUhZZqpkZjMY4FetmM2", "2024-08-15T12:54:35Z", {}, {"patch": [{"op": "add", "path": "/verificationMethod", "value": [{"id": "did:tdw:QmWVViSSXMBoSFskwXV1UtNDtZAdQ41ifyuTeXGNfZnHnA:domain.example#z6MkebuBMK8vqJAt2vrawRKorBpa92EvUkofJfQ9kCGG1Qv6", "controller": "did:tdw:QmWVViSSXMBoSFskwXV1UtNDtZAdQ41ifyuTeXGNfZnHnA:domain.example", "type": "Multikey", "publicKeyMultibase": "z6MkebuBMK8vqJAt2vrawRKorBpa92EvUkofJfQ9kCGG1Qv6"}]}, {"op": "add", "path": "/assertionMethod", "value": ["did:tdw:QmWVViSSXMBoSFskwXV1UtNDtZAdQ41ifyuTeXGNfZnHnA:domain.example#z6MkebuBMK8vqJAt2vrawRKorBpa92EvUkofJfQ9kCGG1Qv6"]}, {"op": "add", "path": "/service", "value": [{"id": "did:tdw:QmWVViSSXMBoSFskwXV1UtNDtZAdQ41ifyuTeXGNfZnHnA:domain.example#domain", "type": "LinkedDomains", "serviceEndpoint": "https://domain.example"}, {"id": "did:tdw:QmWVViSSXMBoSFskwXV1UtNDtZAdQ41ifyuTeXGNfZnHnA:domain.example#whois", "type": "LinkedVerifiablePresentation", "serviceEndpoint": "https://domain.example/.well-known/whois.vc"}]}, {"op": "add", "path": "/authentication", "value": ["did:tdw:QmWVViSSXMBoSFskwXV1UtNDtZAdQ41ifyuTeXGNfZnHnA:domain.example#z6MkebuBMK8vqJAt2vrawRKorBpa92EvUkofJfQ9kCGG1Qv6"]}, {"op": "add", "path": "/@context/2", "value": "https://identity.foundation/.well-known/did-configuration/v1"}, {"op": "add", "path": "/@context/3", "value": "https://identity.foundation/linked-vp/contexts/v1"}]}, [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6Mkq5nYNMjNonx9fRwvuUF4cTV3Jc9r524JVCEEJ9ZnpMh3#z6Mkq5nYNMjNonx9fRwvuUF4cTV3Jc9r524JVCEEJ9ZnpMh3", "created": "2024-08-15T12:54:35Z", "proofPurpose": "authentication", "challenge": "3-QmagjH7LNdeXk3rEtJStbG8yBLVZUhZZqpkZjMY4FetmM2", "proofValue": "z4PQKGetaGv62xkaQfURRFx1dYRSQZdGALWod18t7oZNiX3WpoEqi8drvVDuwNcqzSX2t4XZorRuQ46rt4ywCjrf6"}]]`,
	},
}

var privKeyTestVector = []string{}

const privJWTKey = `{"crv":"P-384","kty":"EC","x":"Y_VO9ZRmTb8zaKkl7d4B3lxLU9A-FiI2Zig01wrC_emxY4oaPAT1_oaTt4BstQ_2","y":"Hl8BQROmOH44cZrhS7uZDo4tSKztPGKNBqX4nILPvl_SH0M6KxTGQR9S7x0QO3Lq","d":"2w79S4p9XT1J_o3G48UxTws8YCK6OVFwwjEH7RXrFt0rTnG8GKYvI-IH3lk4h82Q"}
`

func TestPrivKey(t *testing.T) {
	// is the key ok? Can we parse it and generate a public key from it?
	t.Run("ok", func(t *testing.T) {

		// point, err := base64.URLEncoding.DecodeString(privKeyTestVector[0])
		point, err := base64.URLEncoding.DecodeString(priv_key)
		require.NoError(t, err)
		// elliptic.Unmarshal(elliptic.P384(), point)

		// key, err := ecdh.P256().NewPrivateKey(point)
		// require.NoError(t, err)
		// assert.NotNil(t, key)
		// t.Logf("key length: %d", len(point))
		// require.NoError(t, err)

		// does not work, x and y are nil
		// curve := elliptic.P384()
		// x, y := elliptic.UnmarshalCompressed(elliptic.P384(), point)
		// x, y := elliptic.Unmarshal(curve, point)
		// require.NotNil(t, x)
		// require.NotNil(t, y)

		// rawPoint := asn1.RawValue{}
		// asn1.Unmarshal(point, &rawPoint)
		// t.Logf("rawPoint: %x", rawPoint.Bytes)

		// parse the key and generate the public key
		// parsedKey := ed25519.PrivateKey(point)
		// require.NotNil(t, parsedKey)
		// require.NotNil(t, parsedKey.Public())

		// sig := ed25519.Sign(parsedKey, []byte("test"))
		// assert.NotNil(t, sig)
		// ecPriv, err := x509.ParsePKCS8PrivateKey(point)
		// require.NoError(t, err)
		// assert.NotNil(t, ecPriv)

		// t.Logf("key: %x", point)
		privKey, err := jwk.ParseKey([]byte(jwt_key))
		require.NoError(t, err)
		assert.NotNil(t, privKey)
		t.Logf("privKey: %T", privKey)
		var rawKey ecdsa.PrivateKey
		err = privKey.Raw(&rawKey)
		require.NoError(t, err)

		ecdhKey, err := rawKey.ECDH()
		require.NoError(t, err)

		curve := ecdh.P384()
		curvePKey, err := curve.NewPrivateKey(point)
		t.Logf("curveKey: %x", curvePKey.Bytes())
		require.NoError(t, err)
		require.NotNil(t, curvePKey)
		curvePubKey := curvePKey.PublicKey()

		// t.Logf("curvePubKey: %v", curvePubKey)
		// assert.NotNil(t, curvePubKey)

		// t.Logf("rawKey: %x", ecdhKey.Bytes())
		//
		assert.Equal(t, ecdhKey.PublicKey().Bytes(), curvePubKey.Bytes())

	})
}

func privTestKey(t *testing.T) ecdsa.PrivateKey {
	t.Helper()
	privKey, err := jwk.ParseKey([]byte(jwt_key))
	require.NoError(t, err)
	assert.NotNil(t, privKey)
	t.Logf("privKey: %T", privKey)
	var rawKey ecdsa.PrivateKey
	err = privKey.Raw(&rawKey)
	require.NoError(t, err)
	return rawKey
}

func TestCreate(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	// Can we recreate the log entry from the test vector?
	t.Run("ok - test vector", func(t *testing.T) {
		testLogEntry := LogEntry{}
		testLogEntry.UnmarshalJSONL([]byte(testVector1.log[0]))

		timeFunc = func() time.Time {
			// use the time of the test vector
			return testLogEntry.VersionTime
		}
		defer func() {
			timeFunc = time.Now
		}()

		// use the template of the test vector
		signer := testVector1.signer(t)
		logEntries, err := Create(testVector1.pathTemplate, signer, testLogEntry.Params.NextKeyHashes)

		require.NoError(t, err)
		require.Len(t, logEntries, 1)

		// check if the resulting log entry (including the proof) is the same as the test vector
		assert.Equal(t, testLogEntry, logEntries[0])
	})

	t.Run("ok - ecdsa-jcs-2019", func(t *testing.T) {
		signer, err := NewSigner(CRYPTO_SUITE_ECDSA_JCS_2019)
		require.NoError(t, err)
		require.NoError(t, err)
		log, err := Create("did:tdw:{SCID}:example.com", signer, nil)
		require.NoError(t, err)
		require.Len(t, log, 1)
		err = log.Verify()
		require.NoError(t, err)
	})

	t.Run("ok - eddsa-jcs-2022", func(t *testing.T) {
		signer, err := NewSigner(CRYPTO_SUITE_EDDSA_JCS_2022)
		require.NoError(t, err)
		require.NoError(t, err)
		log, err := Create("did:tdw:{SCID}:example.com", signer, nil)
		require.NoError(t, err)
		require.Len(t, log, 1)
		err = log.Verify()
		require.NoError(t, err)
	})

}

const testLogEntryV0 = `[
  "{SCID}",
  "2024-07-29T17:00:27Z",
  {
    "prerotation": true,
    "updateKeys": [
      "z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc"
    ],
    "nextKeyHashes": [
      "QmcbM5bppyT4yyaL35TQQJ2XdSrSNAhH5t6f4ZcuyR4VSv"
    ],
    "method": "did:tdw:0.3",
    "scid": "{SCID}"
  },
  {
    "value": {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1"
      ],
      "id": "did:tdw:{SCID}:domain.example"
    }
  }
]`

const testVector2 = `[
  "Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu",
  "2024-07-29T17:00:27Z",
  {
    "prerotation": true,
    "updateKeys": [
      "z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc"
    ],
    "nextKeyHashes": [
      "QmcbM5bppyT4yyaL35TQQJ2XdSrSNAhH5t6f4ZcuyR4VSv"
    ],
    "method": "did:tdw:0.3",
    "scid": "Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu"
  },
  {
    "value": {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1"
      ],
      "id": "did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu:domain.example"
    }
  }
]`

func TestTestVectors(t *testing.T) {
	t.Run("vectorPartionInitLogEntry", func(t *testing.T) {
		line := logLine{}
		err := json.Unmarshal([]byte(testLogEntryV0), &line)
		require.NoError(t, err)

		entry, err := line.ToLogEntry()
		require.NoError(t, err)

		jsonA, err := json.Marshal(entry)
		require.NoError(t, err)

		tVector := testLogEntry2(t)
		jsonB, err := json.Marshal(tVector)
		require.NoError(t, err)
		assert.Equal(t, string(jsonA), string(jsonB))
	})
}

func TestVerifyProof(t *testing.T) {
	t.Run("test vector 2", func(t *testing.T) {
		t.Skip("currently unable to verify ecdsa proofs generated by the python implementation")
		entry := LogEntry{}
		err := entry.UnmarshalJSONL([]byte(LogLineTestVector2))
		require.NoError(t, err)
		err = DIDLog{entry}.Verify()
		assert.NoError(t, err)
	})

	t.Run("test vector 3", func(t *testing.T) {
		entry := LogEntry{}
		err := entry.UnmarshalJSONL([]byte(LogLineTestVector3))
		require.NoError(t, err)
		err = DIDLog{entry}.Verify()
		assert.NoError(t, err)
	})
}

func TestUpdate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		signer, err := NewSigner(CRYPTO_SUITE_EDDSA_JCS_2022)
		require.NoError(t, err)
		// params, err := tdw.NewParams([]crypto.PublicKey{signer.Public()}, nil)
		// require.NoError(t, err)

		log, err := Create("did:tdw:{SCID}:example.com", signer, nil)
		require.NoError(t, err)
		require.Len(t, log, 1)

		doc, err := log.Document()
		require.NoError(t, err)
		require.NotNil(t, doc)

		doc["service"] = []interface{}{
			map[string]interface{}{
				"foo-service": "https://example.com/service/1",
			}}

		log, err = Update(log, LogParams{}, doc, signer)
		assert.NoError(t, err)
		assert.Len(t, log, 2)

		updatedDoc, err := log.Document()
		assert.NoError(t, err)
		assert.Equal(t, doc, updatedDoc)

		err = log.Verify()
		assert.NoError(t, err)
	})
}

func testLogEntry1(t *testing.T) LogEntry {
	versionTime, err := time.Parse(time.RFC3339, "2024-06-18T19:25:55Z")
	require.NoError(t, err)

	doc := map[string]interface{}{
		"@context": []string{
			"https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1",
		},
		"id": "did:tdw:domain.example:{SCID}",
	}

	return LogEntry{
		VersionId:   versionId{Hash: "{SCID}"},
		VersionTime: versionTime,
		Params: LogParams{
			Method:        "did:tdw:1",
			Scid:          "{SCID}",
			Prerotation:   true,
			UpdateKeys:    []string{"z82LkqR25TU88tztBEiFydNf4fUPn8oWBANckcmuqgonz9TAbK9a7WGQ5dm7jyqyRMpaRAe"},
			NextKeyHashes: []string{"enkkrohe5ccxyc7zghic6qux5inyzthg2tqka4b57kvtorysc3aa"},
		},
		DocState: docState{Value: doc},
	}
}

const LogLineTestVector1 = `["1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ", "2024-07-29T17:00:27Z", {"prerotation": true, "updateKeys": ["z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc"], "nextKeyHashes": ["QmcbM5bppyT4yyaL35TQQJ2XdSrSNAhH5t6f4ZcuyR4VSv"], "method": "did:tdw:0.3", "scid": "Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu"}, {"value": {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], "id": "did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu:domain.example"}}, [{"type": "DataIntegrityProof", "cryptosuite": "ecdsa-jcs-2019", "verificationMethod": "did:key:z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc#z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc", "created": "2024-07-29T17:00:27Z", "proofPurpose": "authentication", "challenge": "1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ", "proofValue": "zDk24L4vbVrFm5CPQjRD9KoGFNcV6C3ub1ducPQEvDQ39U68GiofAndGbdG9azV6r78gHr1wKnKNPbMz87xtjZtcq9iwN5hjLptM9Lax4UeMWm9Xz7PP4crToj7sZnvyb3x4"}]]`

const LogLineTestVector2 = `["1-QmXWp3RxVCbCVK749eDEGMcuSpHpt23VyKav6TJxgQncCN", "2024-08-15T08:45:54Z", {"prerotation": true, "updateKeys": ["z82Lm4hFND9akT8nJu8WqjQS9t3mLcKLWFu1PaynM6J5KPyHJV4LxMkds6qfiyM7hrUq6vX"], "nextKeyHashes": ["QmedThpP8wtf8f79wRUpdjsTRJN582eVqQ4rQwWaForXux"], "method": "did:tdw:0.3", "scid": "QmbqTjJBnx2MGDcba2ZSzgkRJsCRDXKxeTUctkaUNo2wCW"}, {"value": {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], "id": "did:tdw:QmbqTjJBnx2MGDcba2ZSzgkRJsCRDXKxeTUctkaUNo2wCW:domain.example"}}, [{"type": "DataIntegrityProof", "cryptosuite": "ecdsa-jcs-2019", "verificationMethod": "did:key:z82Lm4hFND9akT8nJu8WqjQS9t3mLcKLWFu1PaynM6J5KPyHJV4LxMkds6qfiyM7hrUq6vX#z82Lm4hFND9akT8nJu8WqjQS9t3mLcKLWFu1PaynM6J5KPyHJV4LxMkds6qfiyM7hrUq6vX", "created": "2024-08-15T08:45:54Z", "proofPurpose": "authentication", "challenge": "1-QmXWp3RxVCbCVK749eDEGMcuSpHpt23VyKav6TJxgQncCN", "proofValue": "z2Tra2ZbYzcmN3Wvjyqr5Z2AvJ83q3AazM2VkfBE8WsJJ4CD6YFhJuMUc2atAcDDUwdgJsoHJ7aiJGmEhLTkooSdJ2PQvuWBPQ7zdRmZ7wfL5TZ6My2d6YtJCPMDoNQK6NQMr"}]]`

// consists of a ed25519 signature
const LogLineTestVector3 = `["1-QmZWJ1h4cnzsUVYXrzPvcDD5tneo4w5g1jaLCJbiX5BAvx", "2024-08-15T09:03:55Z", {"prerotation": true, "updateKeys": ["z6MkpgcFTDewdbqkLyP1bD9gj1NRNQUPhSHeQ5h3eVhJrSHa"], "nextKeyHashes": ["QmX4XAi5QzFAZganGNSdcv7VkjusoAzHhwgbco9o6d4s1n"], "method": "did:tdw:0.3", "scid": "QmWp26RwppBQxA6VUZGeQTG5Xbt9hZxNyTJDsW2C27s5E8"}, {"value": {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], "id": "did:tdw:QmWp26RwppBQxA6VUZGeQTG5Xbt9hZxNyTJDsW2C27s5E8:domain.example"}}, [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpgcFTDewdbqkLyP1bD9gj1NRNQUPhSHeQ5h3eVhJrSHa#z6MkpgcFTDewdbqkLyP1bD9gj1NRNQUPhSHeQ5h3eVhJrSHa", "created": "2024-08-15T09:03:55Z", "proofPurpose": "authentication", "challenge": "1-QmZWJ1h4cnzsUVYXrzPvcDD5tneo4w5g1jaLCJbiX5BAvx", "proofValue": "z5phrZZ1zZqgV1ESRntr7sdcH99tSEeihNrhViPwGqvxQrJVmFCQqQHNKdjniBvK1ux6wLcCm9C4o9mRzVqL8LJFh"}]]`

func logEntryTestVector1(t *testing.T) LogEntry {
	t.Helper()
	return LogEntry{
		VersionId:   versionId{Version: 1, Hash: "QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ"},
		VersionTime: time.Date(2024, 7, 29, 17, 00, 27, 0, time.UTC),
		Params: LogParams{
			Method:        "did:tdw:0.3",
			Scid:          "Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu",
			Prerotation:   true,
			UpdateKeys:    []string{"z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc"},
			NextKeyHashes: []string{"QmcbM5bppyT4yyaL35TQQJ2XdSrSNAhH5t6f4ZcuyR4VSv"},
		},
		DocState: docState{
			Value: map[string]interface{}{
				"@context": []interface{}{
					"https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1",
				},
				"id": "did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu:domain.example",
			},
		},
		Proof: []Proof{{
			Type:               "DataIntegrityProof",
			Cryptosuite:        "ecdsa-jcs-2019",
			VerificationMethod: "did:key:z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc#z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc",
			Created:            "2024-07-29T17:00:27Z",
			ProofPurpose:       "authentication",
			Challenge:          "1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ",
			ProofValue:         "zDk24L4vbVrFm5CPQjRD9KoGFNcV6C3ub1ducPQEvDQ39U68GiofAndGbdG9azV6r78gHr1wKnKNPbMz87xtjZtcq9iwN5hjLptM9Lax4UeMWm9Xz7PP4crToj7sZnvyb3x4",
		}},
	}
}

func TestLogEntryMarshalJSONL(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		entry := logEntryTestVector1(t)
		data, err := entry.MarshalJSONL()

		// canonicalize the test vector so it can be compared
		testVector := []byte(LogLineTestVector1)
		(*jsontext.Value)(&testVector).Canonicalize()

		require.NoError(t, err)
		assert.NotEmpty(t, data)
		assert.Equal(t, string(testVector), string(data))
	})
}

func TestLogEntryUnmarshalJSONL(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		entry := LogEntry{}
		err := entry.UnmarshalJSONL([]byte(LogLineTestVector1))
		require.NoError(t, err)

		assert.Equal(t, logEntryTestVector1(t), entry)
	})
}

func TestParseLog(t *testing.T) {

	t.Run("ok - parse a logline", func(t *testing.T) {
		log, err := ParseLog([]byte(LogLineTestVector1))
		require.NoError(t, err)

		assert.Equal(t, DIDLog{logEntryTestVector1(t)}, log)
	})
}

func testLogEntry2(t *testing.T) LogEntry {
	versionTime, err := time.Parse(time.RFC3339, "2024-07-29T17:00:27Z")
	require.NoError(t, err)

	doc := map[string]interface{}{
		"@context": []string{
			"https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1",
		},
		"id": "did:tdw:{SCID}:domain.example",
	}

	return LogEntry{
		VersionId:   versionId{Hash: "{SCID}"},
		VersionTime: versionTime,
		Params: LogParams{
			Method:        "did:tdw:0.3",
			Scid:          "{SCID}",
			Prerotation:   true,
			UpdateKeys:    []string{"z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc"},
			NextKeyHashes: []string{"QmcbM5bppyT4yyaL35TQQJ2XdSrSNAhH5t6f4ZcuyR4VSv"},
		},
		DocState: docState{Value: doc},
	}
}

// func TestCalculateSCID(t *testing.T) {
// 	t.Run("ok", func(t *testing.T) {
// 		entry := new(LogEntry)
// 		err := entry.UnmarshalJSONL([]byte(testVector1))
// 		require.NoError(t, err, entry)
// 		tdw := NewTrustDIDWeb("did:tdw:domain.example:{SCID}", "ecdsa-jcs-2019")
// 		scid, err := calculateSCID(*entry)
// 		assert.NoError(t, err)
// 		assert.Equal(t, "Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu", scid)
// 	})
// }

func TestCalculateVersionID(t *testing.T) {
	t.Run("ok - without scid", func(t *testing.T) {
		entry := new(LogEntry)
		err := entry.UnmarshalJSONL([]byte(testLogEntryV0))
		require.NoError(t, err, entry)

		versionId, err := DIDLog{*entry}.calculateVersionId(0)
		assert.NoError(t, err)
		assert.Equal(t, "Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu", string(versionId.Hash))
		assert.Equal(t, 0, versionId.Version)
	})

	t.Run("ok - with scid", func(t *testing.T) {
		entry := new(LogEntry)
		err := entry.UnmarshalJSONL([]byte(testVector2))
		require.NoError(t, err, entry)

		versionId, err := DIDLog{*entry}.calculateVersionId(1)
		assert.NoError(t, err)
		assert.Equal(t, "QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ", string(versionId.Hash))
		assert.Equal(t, 1, versionId.Version)
	})
}

func TestEntryHash(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		scid := EntryHash("Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu")
		hash, hashType, err := scid.Digest()
		require.NoError(t, err)
		assert.Equal(t, uint64(0x12), hashType)
		assert.Len(t, hash, 32)
	})

	t.Run("nok - invalid length", func(t *testing.T) {
		scid := EntryHash("Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBK")
		hash, hashType, err := scid.Digest()
		assert.EqualError(t, err, "invalid digest-value length")
		assert.Nil(t, hash)
		assert.Zero(t, hashType)
	})
}

func TestNewScid(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		scid := NewEntryHash([]byte("hello world"), uint64(multicodec.Sha2_256))
		assert.Equal(t, "QmaozNR7DZHQK1ZcU9p7QdrshMvXqWK6gpu5rmrkPdT3L4", string(scid))
		err := scid.Verify([]byte("hello world"))
		assert.NoError(t, err)
	})
}
