package importer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewInfisical(t *testing.T) {
	t.Run("DefaultBaseURL", func(t *testing.T) {
		imp := NewInfisical("token", "proj", "env", "")
		i, ok := imp.(*InfisicalImporter)
		assert.True(t, ok)
		assert.Equal(t, "token", i.token)
		assert.Equal(t, "proj", i.projectID)
		assert.Equal(t, "env", i.env)
		assert.Equal(t, "https://app.infisical.com", i.baseURL)
	})

	t.Run("CustomBaseURL", func(t *testing.T) {
		imp := NewInfisical("token", "proj", "env", "https://custom.infisical.com")
		i, ok := imp.(*InfisicalImporter)
		assert.True(t, ok)
		assert.Equal(t, "https://custom.infisical.com", i.baseURL)
	})
}
