package syncer

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistry_CanonicalTargetIdentityRejectsAmbiguousInputs(t *testing.T) {
	tests := []struct {
		name   string
		config TargetConfig
	}{
		{name: "unknown type", config: TargetConfig{Type: "vault"}},
		{name: "github missing owner", config: TargetConfig{Type: "github", Fields: map[string]string{"repo": "/repo"}}},
		{name: "github too many path segments", config: TargetConfig{Type: "github", Fields: map[string]string{"repo": "owner/repo/extra"}}},
		{name: "github malformed endpoint", config: TargetConfig{Type: "github", Fields: map[string]string{"repo": "owner/repo", "base_url": "%"}}},
		{name: "cloudflare missing account", config: TargetConfig{Type: "cloudflare", Fields: map[string]string{"worker": "worker"}}},
		{name: "cloudflare both resources", config: TargetConfig{Type: "cloudflare", Fields: map[string]string{"account": "account", "worker": "worker", "pages": "pages"}}},
		{name: "cloudflare malformed endpoint", config: TargetConfig{Type: "cloudflare", Fields: map[string]string{"account": "account", "worker": "worker", "base_url": "%"}}},
		{name: "dotenv malformed path is still canonical filesystem identity", config: TargetConfig{Type: "dotenv", Fields: map[string]string{"file": filepath.Join(".", "nested", "..", "state.env")}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity, err := CanonicalTargetIdentity(test.config)
			if test.name == "dotenv malformed path is still canonical filesystem identity" {
				require.NoError(t, err)
				assert.True(t, strings.HasPrefix(identity, "dotenv|"))
				assert.Contains(t, identity, filepath.Base("state.env"))
				return
			}
			require.Error(t, err)
			assert.Empty(t, identity)
		})
	}
}

func TestRegistry_ValidateTargetIdentitiesRejectsInvalidAndEquivalentTargets(t *testing.T) {
	t.Run("invalid target reports its index", func(t *testing.T) {
		err := ValidateTargetIdentities([]TargetConfig{
			{Type: "github", Fields: map[string]string{"repo": "owner/repo"}},
			{Type: "github", Fields: map[string]string{"repo": "invalid"}},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sync target 1")
	})

	t.Run("dotenv canonicalizes relative equivalents", func(t *testing.T) {
		first, err := CanonicalTargetIdentity(TargetConfig{Type: "dotenv", Fields: map[string]string{"file": "./state.env"}})
		require.NoError(t, err)
		second, err := CanonicalTargetIdentity(TargetConfig{Type: "dotenv", Fields: map[string]string{"file": filepath.Clean("state.env")}})
		require.NoError(t, err)
		assert.Equal(t, first, second)
		require.Error(t, ValidateTargetIdentities([]TargetConfig{
			{Type: "dotenv", Fields: map[string]string{"file": "./state.env"}},
			{Type: "dotenv", Fields: map[string]string{"file": filepath.Clean("state.env")}},
		}))
	})
}

func TestRegistry_CanonicalEndpointPreservesSchemeAndPathSemantics(t *testing.T) {
	withoutScheme, err := canonicalEndpoint("Example.test/api/", "https://default.test")
	require.NoError(t, err)
	assert.Equal(t, "example.test/api", withoutScheme)

	withScheme, err := canonicalEndpoint("HTTPS://EXAMPLE.TEST/API/", "https://default.test")
	require.NoError(t, err)
	assert.Equal(t, "https://example.test/API", withScheme)

	defaultValue, err := canonicalEndpoint("  ", "https://DEFAULT.TEST/")
	require.NoError(t, err)
	assert.Equal(t, "https://default.test", defaultValue)
}
