package trustdidweb_test

import (
	"fmt"
	"log"

	tdw "github.com/nuts-foundation/trustdidweb-go"
)

func ExampleCreate() {
	// Create a new signer
	signer, err := tdw.NewSigner(tdw.CRYPTO_SUITE_EDDSA_JCS_2022)
	if err != nil {
		log.Fatal(err)
	}

	// Create a new DIDLog
	doc, err := tdw.NewMinimalDIDDocument("did:tdw:{SCID}:example.com")
	if err != nil {
		log.Fatal(err)
	}

	didLog, err := tdw.Create(doc, signer)
	if err != nil {
		log.Fatal(err)
	}

	// Print the log
	logFile, err := didLog.MarshalText()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(logFile))
}

func ExampleDIDLog_Update() {
	// Create a new signer
	signer, err := tdw.NewSigner(tdw.CRYPTO_SUITE_EDDSA_JCS_2022)
	if err != nil {
		log.Fatal(err)
	}

	// Create a new DIDDocument
	doc, err := tdw.NewMinimalDIDDocument("did:tdw:{SCID}:example.com")
	if err != nil {
		log.Fatal(err)
	}

	// Create a new DIDLog
	didLog, err := tdw.Create(doc, signer)
	if err != nil {
		log.Fatal(err)
	}

	// Get the document from the log
	doc, err = didLog.Document()
	if err != nil {
		log.Fatal(err)
	}

	// Add a service
	doc["service"] = []interface{}{
		map[string]interface{}{
			"id":              fmt.Sprintf("%s#service-1", doc["id"]),
			"type":            "Service",
			"serviceEndpoint": "https://example.com/service/1",
		},
	}

	// Update the log with a new entry containing the updated document
	didLog, err = didLog.Update(tdw.LogParams{}, doc, signer)
	if err != nil {
		log.Fatal(err)
	}

	// Print the log
	logFile, err := didLog.MarshalText()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(logFile))
}

func ExampleDIDLog_Verify() {
	// Create a new signer
	signer, err := tdw.NewSigner(tdw.CRYPTO_SUITE_EDDSA_JCS_2022)
	if err != nil {
		log.Fatal(err)
	}

	// Create a new DIDDocument
	doc, err := tdw.NewMinimalDIDDocument("did:tdw:{SCID}:example.com")
	if err != nil {
		log.Fatal(err)
	}

	didLog, err := tdw.Create(doc, signer)
	if err != nil {
		log.Fatal(err)
	}

	if err := didLog.Verify(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Log is valid")

	// Output:
	// Log is valid
}

func ExampleDIDLog_Deactivate() {
	// Create a new signer
	signer, err := tdw.NewSigner(tdw.CRYPTO_SUITE_EDDSA_JCS_2022)
	if err != nil {
		log.Fatal(err)
	}

	// Create a new DIDDocument
	doc, err := tdw.NewMinimalDIDDocument("did:tdw:{SCID}:example.com")
	if err != nil {
		log.Fatal(err)
	}

	didLog, err := tdw.Create(doc, signer)
	if err != nil {
		log.Fatal(err)
	}

	// Deactivate the log
	didLog, err = didLog.Deactivate(signer)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Is log deactivated: %t\n", didLog.IsDeactivated())

	// Output:
	// Is log deactivated: true
}
