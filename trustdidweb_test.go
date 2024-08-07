package trustdidweb

import (
	"crypto/ecdh"
	"crypto/ecdsa"
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

func TestNewTrustDIDWeb(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pathTemplate := "did:tdw:example.com:dids:{SCID}"
		trustDIDWeb := NewTrustDIDWeb(pathTemplate, "ecdsa-jcs-2019")
		assert.NotNil(t, trustDIDWeb)
	})
}

func TestRenderPathTemplate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pathTemplate := "did:tdw:example.com:dids:{SCID}"
		trustDIDWeb := NewTrustDIDWeb(pathTemplate, "ecdsa-jcs-2019")
		scid := "123456789abcdefghi"
		path := trustDIDWeb.renderPathTemplate(scid)
		assert.Equal(t, "did:tdw:example.com:dids:123456789abcdefghi", path)
	})
}

// const priv_key = "9MfszFIPn52i1lOlUvPI_yG077a9vY8leEmJ61aDJf4D3LwT49EG1Mi3hWr7riVv"
const priv_key = "XfWwd4e0TfIQq4t53mpf0Ut7-KeQM3jB4mJKgeU40a2mn8zN0c-ldzgfu5AOcIFw"
const pub_key = "AoVvb94bIG23mP5JuVBHV8KW5b1f95aTDDpXtYqT-LlrCx9xKPgh02d3WNjbkOHNJw"
const jwt_key = `{"crv":"P-384","kty":"EC","x":"hW9v3hsgbbeY_km5UEdXwpblvV_3lpMMOle1ipP4uWsLH3Eo-CHTZ3dY2NuQ4c0n","y":"n0ahfQKvYV18HkFQrEN6DS-bC4r4zAWFsjFol3f61c5wiTooeifBpyGoNfrggDs2","d":"XfWwd4e0TfIQq4t53mpf0Ut7-KeQM3jB4mJKgeU40a2mn8zN0c-ldzgfu5AOcIFw"}'
`

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
	t.Run("ok - test vector", func(t *testing.T) {
		testLogEntry := logEntryTestVector1(t)

		timeFunc = func() time.Time {
			// use the time of the test vector
			return testLogEntry.VersionTime
		}
		defer func() {
			timeFunc = time.Now
		}()

		// use the params of the test vector
		params := testLogEntry.Params

		params.Scid = ""

		// use the template of the test vector
		pathTemplate := "did:tdw:{SCID}:domain.example"
		tdw := NewTrustDIDWeb(pathTemplate, "ecdsa-jcs-2019")
		privKey := privTestKey(t)

		logEntries, err := tdw.Create(params, &privKey)
		require.NoError(t, err)
		require.Len(t, logEntries, 1)
		entry := logEntries[0]
		// check the hash and scid with the test vector
		assert.Equal(t, "Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu", entry.Params.Scid, "SCID must match")
		assert.Equal(t, "QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ", string(entry.VersionId.Hash), "Hash must match")
		assert.Equal(t, 1, entry.VersionId.Version, "version must match")
		assert.Len(t, entry.Proof, 1, "proof must be present")

		// NOTE: proof verification will not work since the test vector uses a different key

		// privKey, err := jwk.ParseKey([]byte(privJWTKey))
		// require.NoError(t, err)
		// assert.NotNil(t, privKey)
		// var rawKey ecdsa.PrivateKey
		// err = privKey.Raw(&rawKey)
		// require.NoError(t, err)

		// privKey, err := ecdh.P384().NewPrivateKey([]byte(priv_key))
		// var rawKey ecdsa.PrivateKey
		// err = privKey.k
		// require.NoError(t, err)
		// require.NoError(t, err)

		// rawPrivKey, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(priv_key)
		// require.NoError(t, err)
		// rawPubKey, err := base64.URLEncoding.DecodeString(pub_key)
		// rawPubKey, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(pub_key)
		// require.NoError(t, err)

		// t.Logf("rawPubKey: %x", rawPubKey)

		// pubKey, err := ecdh.P384().NewPublicKey(pointBytes)
		// require.NoError(t, err)

		// x, y := elliptic.UnmarshalCompressed(elliptic.P384(), rawPubKey)
		// require.NotNil(t, x)
		// pubKey := &ecdsa.PublicKey{
		// 	Curve: elliptic.P384(),
		// 	X:     x,
		// 	Y:     y,
		// }

		// privKey := &ecdsa.PrivateKey{
		// 	PublicKey: *pubKey,
		// 	D:         big.NewInt(0).SetBytes(rawPrivKey),
		// }

		// t.Logf("x: %s", x.String())
		// t.Logf("y: %s", y.String())

		// xStr := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(x.Bytes())
		// yStr := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(y.Bytes())
		// t.Logf("xStr: %s", xStr)
		// t.Logf("yStr: %s", yStr)

		// jwkKey, err := jwk.New(privKey)
		// require.NoError(t, err)
		// jwtMap, err := jwkKey.AsMap(context.Background())
		// require.NoError(t, err)
		// t.Logf("jwtMap: %+v", jwtMap)

		// proof, err := trustDIDWeb.buildProof(entry, &privKey)
		// proof := entry.Proof[0]
		// // require.NoError(t, err)
		// // assert.NotNil(t, proof)
		// t.Logf("proof: %+v", proof)
		// err = tdw.verifyProof(entry)
		//
		// assert.NoError(t, err)
		// assert.True(t, false)
	})

	t.Run("ok", func(t *testing.T) {
		tdw := NewTrustDIDWeb("did:example.com:did:{SCID}", "ecdsa-jcs-2019")
		signer, err := tdw.NewSigner()
		require.NoError(t, err)
		pubKey := signer.Public()
		params, err := tdw.NewParams(pubKey.(*ecdsa.PublicKey))
		require.NoError(t, err)
		log, err := tdw.Create(*params, signer)
		t.Logf("entries: %+v", log)
		require.NoError(t, err)
		require.Len(t, log, 1)
		err = log.Verify()
		require.NoError(t, err)
	})
}

const testVector1 = `[
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
		err := json.Unmarshal([]byte(testVector1), &line)
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
	t.Run("test vector 1", func(t *testing.T) {
		t.Skip("currently unable to verify ecdsa proofs generated by the python implementation")
		entry := LogEntry{}
		err := entry.UnmarshalJSONL([]byte(LogLineTestVector1))
		require.NoError(t, err)
		err = DIDLog{entry}.Verify()
		assert.NoError(t, err)
	})
}

func TestUpdate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		tdw := NewTrustDIDWeb("did:example.com:did:{SCID}", "ecdsa-jcs-2019")
		signer, err := tdw.NewSigner()
		require.NoError(t, err)
		params, err := tdw.NewParams(signer.Public().(*ecdsa.PublicKey))
		require.NoError(t, err)

		log, err := tdw.Create(*params, signer)
		require.NoError(t, err)
		require.Len(t, log, 1)

		doc, err := log.Document()
		require.NoError(t, err)
		require.NotNil(t, doc)

		doc["service"] = []interface{}{
			map[string]interface{}{
				"foo-service": "https://example.com/service/1",
			}}

		log, err = tdw.Update(log, *params, doc, signer)
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
			Hash:          "sha3-256",
			Prerotation:   true,
			UpdateKeys:    []string{"z82LkqR25TU88tztBEiFydNf4fUPn8oWBANckcmuqgonz9TAbK9a7WGQ5dm7jyqyRMpaRAe"},
			NextKeyHashes: []string{"enkkrohe5ccxyc7zghic6qux5inyzthg2tqka4b57kvtorysc3aa"},
		},
		DocState: docState{Value: doc},
	}
}

const LogLineTestVector1 = `["1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ", "2024-07-29T17:00:27Z", {"prerotation": true, "updateKeys": ["z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc"], "nextKeyHashes": ["QmcbM5bppyT4yyaL35TQQJ2XdSrSNAhH5t6f4ZcuyR4VSv"], "method": "did:tdw:0.3", "scid": "Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu"}, {"value": {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], "id": "did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu:domain.example"}}, [{"type": "DataIntegrityProof", "cryptosuite": "ecdsa-jcs-2019", "verificationMethod": "did:key:z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc#z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc", "created": "2024-07-29T17:00:27Z", "proofPurpose": "authentication", "challenge": "1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ", "proofValue": "zDk24L4vbVrFm5CPQjRD9KoGFNcV6C3ub1ducPQEvDQ39U68GiofAndGbdG9azV6r78gHr1wKnKNPbMz87xtjZtcq9iwN5hjLptM9Lax4UeMWm9Xz7PP4crToj7sZnvyb3x4"}]]`

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
			Hash:          "sha3-256",
			Prerotation:   true,
			UpdateKeys:    []string{"z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc"},
			NextKeyHashes: []string{"QmcbM5bppyT4yyaL35TQQJ2XdSrSNAhH5t6f4ZcuyR4VSv"},
		},
		DocState: docState{Value: doc},
	}
}

func TestCalculateSCID(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		entry := new(LogEntry)
		err := entry.UnmarshalJSONL([]byte(testVector1))
		require.NoError(t, err, entry)
		tdw := NewTrustDIDWeb("did:tdw:domain.example:{SCID}", "ecdsa-jcs-2019")
		scid, err := tdw.calculateSCID(*entry)
		assert.NoError(t, err)
		assert.Equal(t, "Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu", scid)
	})
}

func TestCalculateVersionID(t *testing.T) {
	t.Run("ok - without scid", func(t *testing.T) {
		entry := new(LogEntry)
		err := entry.UnmarshalJSONL([]byte(testVector1))
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
