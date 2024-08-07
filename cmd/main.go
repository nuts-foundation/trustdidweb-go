package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"reflect"

	"github.com/go-json-experiment/json/jsontext"
	"github.com/nuts-foundation/trustdidweb-go"
)

func main() {
	// Set the log level to debug and writer to stdout
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(logHandler))

	// Create a new TrustDIDWeb instance with a template and a crypto suite
	tdw := trustdidweb.NewTrustDIDWeb("did:tdw:example.com:{SCID}", "ecdsa-jcs-2019")

	// Create a new signer
	signer, err := tdw.NewSigner()
	if err != nil {
		panic(err)
	}

	// Configure the Parameters
	// https://bcgov.github.io/trustdidweb/#didtdw-did-method-parameters
	params, err := tdw.NewParams(signer.Public())
	if err != nil {
		panic(err)
	}
	// Create a new DIDLog
	log, err := tdw.Create(*params, signer)
	if err != nil {
		panic(err)
	}

	// Print the entry line:
	entry := log[0]
	entryLine, err := entry.MarshalJSONL()
	if err != nil {
		panic(err)
	}
	slog.Debug("entry created successfully", "jsonline", string(entryLine))
	(*jsontext.Value)(&entryLine).Indent("", "  ")
	fmt.Println(string(entryLine))

	// Print the resulting document:
	doc, err := log.Document()
	if err != nil {
		panic(err)
	}
	jsonDoc, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	(*jsontext.Value)(&jsonDoc).Indent("", "  ")
	fmt.Println(string(jsonDoc))

	// Validate the log
	if err := log.Verify(); err != nil {
		panic(err)
	}

	// Update the document:

	// Create a copy of the document and add a service
	newDoc := doc
	newDoc["service"] = []interface{}{
		map[string]interface{}{
			"id":              "did:tdw:example.com:123456789abcdefghi#service-1",
			"type":            "Service",
			"serviceEndpoint": "https://example.com/service/1",
		},
	}

	// Update the log
	log, err = tdw.Update(log, *params, newDoc, signer)
	if err != nil {
		panic(err)
	}

	// Print the updated entry line:
	updateEntry := log[1]
	updateEntryLine, err := updateEntry.MarshalJSONL()
	if err != nil {
		panic(err)
	}
	(*jsontext.Value)(&updateEntryLine).Indent("", "  ")
	fmt.Println("Updated Entry")
	fmt.Println(string(updateEntryLine))

	// Print the updated document:
	updatedDoc, err := log.Document()
	if err != nil {
		panic(err)
	}
	updatedJsonDoc, err := json.Marshal(updatedDoc)
	if err != nil {
		panic(err)
	}
	(*jsontext.Value)(&updatedJsonDoc).Indent("", "  ")
	fmt.Println("Updated Document")
	fmt.Println(string(updatedJsonDoc))

	// Validate the updated log
	if err := log.Verify(); err != nil {
		panic(err)
	}

	// Print the log
	logfile, err := log.MarshalText()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(logfile))

	// try to parse the log
	parsedLog, err := trustdidweb.ParseLog(logfile)
	if err != nil {
		panic(err)
	}

	if len(parsedLog) != 2 {
		panic("parsed log does not have the correct number of entries")
	}

	// Print the parsed log
	parsedLogfile, err := parsedLog.MarshalText()
	if err != nil {
		panic(err)
	}
	fmt.Println("Parsed Log:")
	fmt.Println(string(parsedLogfile))

	// compare the documents of the parsed log and the original log
	doc2, err := parsedLog.Document()
	if err != nil {
		panic(err)
	}
	doc2Json, err := json.Marshal(doc2)
	if err != nil {
		panic(err)
	}
	(*jsontext.Value)(&doc2Json).Indent("", "  ")
	fmt.Println("Updated Document")
	fmt.Println(string(doc2Json))

	areEqual := reflect.DeepEqual(doc, doc2)
	fmt.Println("Are the documents equal?", areEqual)
}
