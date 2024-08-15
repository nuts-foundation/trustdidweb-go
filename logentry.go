package trustdidweb

import (
	"fmt"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/multiformats/go-multicodec"
)

type LogEntry struct {
	VersionId   versionId `json:"versionId"`
	VersionTime time.Time `json:"versionTime"`
	Params      LogParams `json:"params"`
	DocState    docState  `json:"docState,omitempty"`
	Proof       []Proof   `json:"proof,omitempty"`
}

// logLine is an intermidiate representation of a log entry for JSON marshalling
type logLine []interface{}

func (l *logLine) ToLogEntry() (LogEntry, error) {

	type logLineStruct struct {
		VersionID   interface{} `json:"versionId"`
		VersionTime interface{} `json:"versionTime"`
		Params      interface{} `json:"params"`
		DocState    interface{} `json:"docState"`
		Proof       interface{} `json:"proof"`
	}

	lls := logLineStruct{
		VersionID:   (*l)[0],
		VersionTime: (*l)[1],
		Params:      (*l)[2],
		DocState:    (*l)[3],
		// Proof:       (*l)[4],
	}

	if len(*l) == 5 {
		lls.Proof = (*l)[4]
	} else {
		lls.Proof = nil
	}

	lBytes, err := json.Marshal(lls)
	if err != nil {
		return LogEntry{}, err
	}
	entry := LogEntry{}
	err = json.Unmarshal(lBytes, &entry)
	if err != nil {
		return LogEntry{}, err
	}
	return entry, nil
}

func (l *LogEntry) UnmarshalJSONL(b []byte) error {
	line := logLine{}
	// line := []interface{}{}
	if err := json.Unmarshal(b, &line); err != nil {
		return err
	}

	entry, err := line.ToLogEntry()
	if err != nil {
		return err
	}

	*l = entry
	return nil
}

// MarshalJSONL returns the JSON-line representation of the log entry
func (l LogEntry) MarshalJSONL() ([]byte, error) {
	line := []interface{}{l.VersionId, l.VersionTime, l.Params, l.DocState}

	if len(l.Proof) > 0 {
		line = append(line, l.Proof)
	}

	b, err := json.Marshal(line)
	if err != nil {
		return nil, err
	}
	(*jsontext.Value)(&b).Canonicalize()
	return b, nil
}

func (entry LogEntry) calculateEntryHash(prevVersionId versionId) (string, error) {
	// a hash is calulated over the entry without proof
	entry.Proof = nil
	// fmt.Print("\n\ncalculateEntryHash:\n\n")
	// fmt.Printf("entry: %v\n", entry)

	// Canonicalized version of the first log entry
	entry.VersionId = prevVersionId
	b, err := entry.MarshalJSONL()
	if err != nil {
		return "", err
	}

	fmt.Printf("b: %s\n", b)

	entryHash := NewEntryHash(b, uint64(multicodec.Sha2_256))
	if entryHash == "" {
		return "", fmt.Errorf("failed to calculate entry hash")
	}

	return string(entryHash), nil
}
