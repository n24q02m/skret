package provider_test

import (
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
)

func TestErrors(t *testing.T) {
	assert.Equal(t, "secret not found", provider.ErrNotFound.Error())
	assert.Equal(t, "provider does not support this operation", provider.ErrCapabilityNotSupported.Error())
}

func TestStructs(t *testing.T) {
	t.Run("Secret", func(t *testing.T) {
		s := provider.Secret{
			Key:     "test-key",
			Value:   "test-value",
			Version: 1,
			Meta: provider.SecretMeta{
				Description: "test-description",
			},
		}
		assert.Equal(t, "test-key", s.Key)
		assert.Equal(t, "test-value", s.Value)
		assert.Equal(t, int64(1), s.Version)
		assert.Equal(t, "test-description", s.Meta.Description)
	})

	t.Run("Capabilities", func(t *testing.T) {
		c := provider.Capabilities{
			Write:      true,
			Versioning: true,
		}
		assert.True(t, c.Write)
		assert.True(t, c.Versioning)
		assert.False(t, c.Tagging)
	})
}
