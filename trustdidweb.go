package trustdidweb

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"text/template"
	"time"
)

const TDWMethodv1 = "did:tdw:1"

type LogEntry struct {
	hash        []byte
	versionId   int
	versionTime time.Time
	params      LogParams
	value       interface{}
	proof       interface{}
}

type LogParams struct {
	method        string
	scid          string
	updateKeys    []string
	hash          string
	cryptosuite   string
	prerotation   bool
	nextKeyHashes []string
	moved         string
	deactivated   bool
	ttl           int
}

type TrustDIDWeb struct {
	pathTemplate *template.Template
}

func NewTrustDIDWeb(pathTemplateString string) (*TrustDIDWeb, error) {
	pathTemplate, err := template.New("pathTemplate").Parse(pathTemplateString)
	if err != nil {
		return nil, err
	}
	return &TrustDIDWeb{
		pathTemplate: pathTemplate,
	}, nil
}

func (t *TrustDIDWeb) renderPathTemplate(scid string) (*url.URL, error) {
	buf := new(bytes.Buffer)
	err := t.pathTemplate.Execute(buf, struct{ SCID string }{scid})
	if err != nil {
		return nil, err
	}
	return url.Parse(buf.String())
}

func (t *TrustDIDWeb) Create(scid string) (LogEntry, error) {
	path, err := t.renderPathTemplate(scid)
	if err != nil {
		return LogEntry{}, err
	}

	didTemplate := "did:tdw:%s"
	didPath := strings.ReplaceAll(path.String(), "/", ":")

	didString := fmt.Sprintf(didTemplate, didPath)

	return LogEntry{
		value: map[string]interface{}{"id": didString},
		params: LogParams{method: TDWMethodv1,
			scid:        scid,
			hash:        "sha256",
			cryptosuite: "eddsa-jcs-2022",
			prerotation: false,
			deactivated: false,
		},
	}, nil
}
