package trustdidweb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTrustDIDWeb(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pathTemplate := "example.com/dids/{{.SCID}}"
		trustDIDWeb, err := NewTrustDIDWeb(pathTemplate)
		assert.NoError(t, err)
		assert.NotNil(t, trustDIDWeb)
	})
	t.Run("err - invalid template", func(t *testing.T) {
		pathTemplate := "example.com/dids/{{SCID}}"
		trustDIDWeb, err := NewTrustDIDWeb(pathTemplate)
		assert.EqualError(t, err, "template: pathTemplate:1: function \"SCID\" not defined")
		assert.Nil(t, trustDIDWeb)
	})
}

func TestRenderPathTemplate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pathTemplate := "example.com/dids/{{.SCID}}"
		trustDIDWeb, _ := NewTrustDIDWeb(pathTemplate)
		scid := "123456789abcdefghi"
		path, err := trustDIDWeb.renderPathTemplate(scid)
		assert.NoError(t, err)
		assert.Equal(t, "example.com/dids/123456789abcdefghi", path.String())
	})

	t.Run("err - invalid template", func(t *testing.T) {
		pathTemplate := "example.com/dids/{{.invalid}}"
		trustDIDWeb, err := NewTrustDIDWeb(pathTemplate)
		require.NoError(t, err)
		scid := "123456789abcdefghi"
		path, err := trustDIDWeb.renderPathTemplate(scid)
		assert.EqualError(t, err, "template: pathTemplate:1:19: executing \"pathTemplate\" at <.invalid>: can't evaluate field invalid in type struct { SCID string }")
		assert.Empty(t, path)
	})
}

func TestCreate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pathTemplate := "example.com/dids/{{.SCID}}"
		trustDIDWeb, _ := NewTrustDIDWeb(pathTemplate)
		scid := "123456789abcdefghi"
		logEntry, err := trustDIDWeb.Create(scid)
		assert.NoError(t, err)
		assert.Equal(t, map[string]interface{}{"id": "did:tdw:example.com:dids:123456789abcdefghi"}, logEntry.value)
		assert.Equal(t, LogParams{method: "did:tdw:1", scid: "123456789abcdefghi", hash: "sha256", cryptosuite: "eddsa-jcs-2022", deactivated: false}, logEntry.params)
	})
}
