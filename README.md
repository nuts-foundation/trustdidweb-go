# trustdidweb-go

This repository contains a highly experimental and unstable implementation of the [Trust DID Web DID-Method specification](https://bcgov.github.io/trustdidweb/).

Its purpose now is to get some hands-on experience with the specification. If we find it useful, we might continue to develop it further into a more stable implementation.

Do not use this in production!

## Example usage

```go
    // create a new TrustDIDWeb instance
    tdw := trustdidweb.NewTrustDIDWeb("did:tdw:example.com:{SCID}", "ecdsa-jcs-2019")
	signer, _ := tdw.NewSigner()
	params, _ := tdw.NewParams(signer.Public())
    // create a DIDLog
	log, _ := tdw.Create(*params, signer)
    // get the DID Document
	doc, _ := log.Document()

    // verify a log
	if err := log.Verify(); err != nil {
		panic(err)
	}

    // update the document with a new service
	doc["service"] = []interface{}{
		map[string]interface{}{
			"id":              "did:tdw:example.com:123456789abcdefghi#service-1",
			"type":            "Service",
			"serviceEndpoint": "https://example.com/service/1",
		},
	}

	// Update the log
	log, _ = tdw.Update(log, *params, newDoc, signer)

	// get the updated document:
	updatedDoc, err := log.Document()

    // verify the log
	if err := log.Verify(); err != nil {
		panic(err)
	}

    // Marshal the log to a did-log-file which can be hosted on a n well-known endpoint
    logFile, _ := log.MarshalText()

    // read a log from a did-log-file
    newLog := new(DIDLog)
    err := newLog.UnmarshalText(logfile)
    if err != nil {
        panic(err)
    }
```
