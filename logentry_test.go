package trustdidweb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogEntry_copy(t *testing.T) {
	t.Run("copy returns a deep copy of the entry", func(t *testing.T) {
		entry := LogEntry{}
		err := entry.UnmarshalJSONL([]byte(testVector1.log[0]))
		require.NoError(t, err)

		entryCopy := entry.copy()
		assert.Equal(t, entry, entryCopy)
		assert.False(t, &entry == &entryCopy)

		entry.DocState["id"] = "new-id"
		assert.NotEqual(t, entry.DocState["id"], entryCopy.DocState["id"])
	})
}
