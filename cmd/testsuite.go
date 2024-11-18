package main

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/lestrrat-go/jwx/jwk"
	tdw "github.com/nuts-foundation/trustdidweb-go"
)

type TestEntry struct {
	Id          string           `json:"id"`
	Type        []string         `json:"type"`
	Purpose     string           `json:"purpose"`
	Input       string           `json:"input,omitempty"`
	Expect      string           `json:"expect,omitempty"`
	SigningKey  jwk.Key          `json:"signingKey,omitempty"`
	Params      tdw.LogParams    `json:"params,omitempty"`
	DIDDocument tdw.DIDDocument  `json:"didDocument,omitempty"`
	Options     TestEntryOptions `json:"options,omitempty"`
}

type TestEntryOptions struct {
	SigningTime time.Time `json:"signingTime,format:RFC3339"`
}

const CreationTest = "CreationTest"
const UpdateTest = "UpdateTest"
const VerificationTest = "VerificationTest"
const PositiveEvaluationTest = "PositiveEvaluationTest"
const NegativeEvaluationTest = "NegativeEvaluationTest"

type genEntryFunc func() (entry TestEntry, input tdw.DIDLog, expect tdw.DIDLog, err error)

func GenerateTests() {
	entries := []TestEntry{}

	for _, gen := range []genEntryFunc{genTC001, genTU001, genTV001, genTV002} {
		entry, didLogInput, didLogExpect, err := gen()
		if err != nil {
			log.Fatal(err)
		}

		if didLogExpect != nil {
			// base the signing time on the actual time of the last entry
			entry.Options.SigningTime = didLogExpect[len(didLogExpect)-1].VersionTime
		}

		if didLogInput != nil {
			inputRaw, err := didLogInput.MarshalText()
			if err != nil {
				log.Fatal(err)
			}

			if err := os.WriteFile(entry.Input, inputRaw, 0644); err != nil {
				log.Fatal(err)
			}
		}
		if didLogExpect != nil {
			expectedRaw, err := didLogExpect.MarshalText()
			if err != nil {
				log.Fatal(err)
			}

			if err := os.WriteFile(entry.Expect, expectedRaw, 0644); err != nil {
				log.Fatal(err)
			}
		}

		entries = append(entries, entry)
	}

	entriesJson, err := json.Marshal(entries, jsontext.WithIndent("  "))
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile("testdata/manifest.json", entriesJson, 0644); err != nil {
		log.Fatal(err)
	}
}

func genTC001() (entry TestEntry, input tdw.DIDLog, expect tdw.DIDLog, err error) {

	// Create a new document
	entry = TestEntry{
		Id:      "tc001",
		Type:    []string{CreationTest, PositiveEvaluationTest},
		Purpose: "Create a new log",
		Expect:  "testdata/tc001-expect.json",
		Options: TestEntryOptions{},
	}

	// Create a new signer
	signer, err := tdw.NewSigner(tdw.CRYPTO_SUITE_EDDSA_JCS_2022)
	if err != nil {
		log.Fatal(err)
	}
	signingKey, err := jwk.New(*signer.(*ed25519.PrivateKey))
	if err != nil {
		log.Fatal(err)
	}
	entry.SigningKey = signingKey

	doc, err := tdw.NewMinimalDIDDocument("did:tdw:{SCID}:example.com")
	if err != nil {
		log.Fatal(err)
	}
	entry.DIDDocument = doc

	expect, err = tdw.Create(doc, signer)
	if err != nil {
		log.Fatal(err)
	}

	return
}

func genTU001() (entry TestEntry, input tdw.DIDLog, expect tdw.DIDLog, err error) {

	firstEntry, _, input, err := genTC001()
	if err != nil {
		log.Fatal(err)
	}

	// Create a new document
	entry = TestEntry{
		Id:      "tu001",
		Type:    []string{UpdateTest, PositiveEvaluationTest},
		Purpose: "Update a log with a service",
		Input:   "testdata/tu001-input.json",
		Expect:  "testdata/tu001-expect.json",
		Options: TestEntryOptions{},
	}
	jwkKey := firstEntry.SigningKey
	entry.SigningKey = jwkKey

	signingKey := ed25519.PrivateKey{}
	if err := jwkKey.Raw(&signingKey); err != nil {
		log.Fatal(err)
	}

	doc, err := input.Document()
	if err != nil {
		log.Fatal(err)
	}

	doc["service"] = []map[string]interface{}{{
		"id":              fmt.Sprintf("did:tdw:%s:example.com#service-1", input[0].Params.Scid),
		"type":            "ExampleService",
		"serviceEndpoint": "https://example.com/service/1",
	}}

	entry.DIDDocument = doc

	expect, err = input.Update(tdw.LogParams{}, doc, signingKey)
	if err != nil {
		log.Fatal(err)
	}

	return
}

func genTV001() (entry TestEntry, input tdw.DIDLog, expect tdw.DIDLog, err error) {
	entry = TestEntry{
		Id:      "tv001",
		Type:    []string{VerificationTest, PositiveEvaluationTest},
		Purpose: "Verify a log",
		Input:   "testdata/tc001-expect.json",
	}
	return
}

func genTV002() (entry TestEntry, input tdw.DIDLog, expect tdw.DIDLog, err error) {
	_, _, input, err = genTC001()
	if err != nil {
		log.Fatal(err)
	}

	input[0].Proof[0].ProofValue = "invalid"

	entry = TestEntry{
		Id:      "tv002",
		Type:    []string{VerificationTest, NegativeEvaluationTest},
		Purpose: "Verify a log with an invalid signature",
		Input:   "testdata/tv002-input.json",
	}
	return
}
