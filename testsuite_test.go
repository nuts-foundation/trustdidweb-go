package trustdidweb

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testEntry struct {
	Id          string                 `json:"id"`
	Type        []string               `json:"type"`
	Purpose     string                 `json:"purpose"`
	Input       string                 `json:"input,omitempty"`
	Expect      string                 `json:"expect"`
	SigningKey  map[string]interface{} `json:"signingKey,omitempty"`
	Params      LogParams              `json:"params,omitempty"`
	DIDDocument DIDDocument            `json:"didDocument"`
	Options     testEntryOptions       `json:"options,omitempty"`
}
type testEntryOptions struct {
	SigningTime time.Time `json:"signingTime,format:RFC3339"`
}

func (e testEntry) key(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	jwkKey, _ := json.Marshal(e.SigningKey)
	key, err := jwk.ParseKey(jwkKey)
	if err != nil {
		t.Fatalf("failed to get private key: %s", err)
	}
	privKey := ed25519.PrivateKey{}
	if err := key.Raw(&privKey); err != nil {
		t.Fatalf("failed to get private key: %s", err)
	}
	return privKey
}

func TestSuite(t *testing.T) {

	const CreationTest = "CreationTest"
	const VerificationTest = "VerificationTest"
	const UpdateTest = "UpdateTest"
	const PositiveEvaluationTest = "PositiveEvaluationTest"
	const NegativeEvaluationTest = "NegativeEvaluationTest"

	t.Run("TestSuite", func(t *testing.T) {

		manifestFile := "testdata/manifest.json"

		// Load the manifest
		manifest, err := os.ReadFile(manifestFile)
		if err != nil {
			t.Fatalf("failed to read manifest file: %s", err)
		}

		// Unmarshal the manifest
		var entries []testEntry
		if err := json.Unmarshal(manifest, &entries); err != nil {
			t.Fatalf("failed to unmarshal manifest file: %s", err)
		}

		// Run the TestSuite
		for _, entry := range entries {
			name := fmt.Sprintf("%s-%s", entry.Id, entry.Purpose)

			t.Run(name, func(t *testing.T) {

				if !entry.Options.SigningTime.IsZero() {
					oldTimeFunc := timeFunc
					defer func() {
						timeFunc = oldTimeFunc
					}()
					timeFunc = func() time.Time {
						return entry.Options.SigningTime
					}
				}

				var resLog DIDLog
				switch entry.Type[0] {
				case CreationTest:
					privKey := entry.key(t)
					resLog, err = Create(entry.DIDDocument, privKey)
					if err != nil {
						require.NoError(t, err)
					}
				case UpdateTest:
					privKey := entry.key(t)
					inputFile, err := os.ReadFile(entry.Input)
					if err != nil {
						t.Fatalf("failed to read input file: %s", err)
					}
					inputLog, err := ParseLog(inputFile)
					if err != nil {
						t.Fatalf("failed to parse input file: %s", err)
					}
					resLog, err = inputLog.Update(entry.Params, entry.DIDDocument, privKey)
					if err != nil {
						t.Fatalf("failed to update DIDDocument: %s", err)
					}

					// check if the documents match
					if len(entry.DIDDocument) > 0 {
						actualDoc, err := resLog.Document()
						if err != nil {
							t.Fatalf("failed to get DIDDocument: %s", err)
						}
						assert.Equal(t, entry.DIDDocument, actualDoc)
					}
				case VerificationTest:
					inputFile, err := os.ReadFile(entry.Input)
					if err != nil {
						t.Fatalf("failed to read input file: %s", err)
					}
					inputLog, err := ParseLog(inputFile)
					if err != nil {
						t.Fatalf("failed to parse input file: %s", err)
					}
					err = inputLog.Verify()
					if slices.Contains(entry.Type, PositiveEvaluationTest) {
						assert.NoError(t, err)
					} else {
						assert.Error(t, err)
					}
				default:
					t.Skipf("unsupported test type: %s", entry.Type[0])
				}

				// only check if there is an expected result defined
				if entry.Expect != "" {
					actual, err := resLog.MarshalText()
					if err != nil {
						t.Fatalf("failed to marshal DIDDocument")
					}
					expected, err := os.ReadFile(entry.Expect)
					if err != nil {
						t.Fatalf("failed to read expected file: %s", err)
					}
					assert.Equal(t, string(expected), string(actual))
				}

			})
		}
	})
}
