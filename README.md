# trustdidweb-go

This repository contains a highly experimental and unstable implementation of the [Trust DID Web DID-Method specification](https://bcgov.github.io/trustdidweb/).

Its purpose now is to get some hands-on experience with the specification. If we find it useful, we might continue to develop it further into a more stable implementation.

Do not use this in production!

## Example usage

```go
signer, _ := NewSigner("eddsa-jcs-2022")
// create a new log
log := Create("did:tdw:{SCID}:example.com}", signer, nil)
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
log, _ = Update(log, LogParams{}, newDoc, signer)

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

## TODO

Following thing are still missing (not in a particular order):

- Better test coverage
- Deactivation of a log
- Add a resolver
- Validation of pre-rotations keys/hashes
- Generation of a `did:web` document from a log
- Cleanup of the code
- Support for witness signatures
