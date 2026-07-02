package syncer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistry_Build(t *testing.T) {
	t.Run("unknown type", func(t *testing.T) {
		_, err := Build([]TargetConfig{{Type: "vault"}})
		require.ErrorContains(t, err, `unknown sync target "vault"`)
	})
	t.Run("dotenv default file", func(t *testing.T) {
		s, err := Build([]TargetConfig{{Type: "dotenv", Fields: map[string]string{}}})
		require.NoError(t, err)
		require.Len(t, s, 1)
		assert.Equal(t, "dotenv", s[0].Name())
	})
	t.Run("github needs repo field", func(t *testing.T) {
		_, err := Build([]TargetConfig{{Type: "github", Token: "t", Fields: map[string]string{}}})
		require.ErrorContains(t, err, "repo")
	})
	t.Run("multi-target", func(t *testing.T) {
		s, err := Build([]TargetConfig{
			{Type: "dotenv", Fields: map[string]string{"file": ".env"}},
			{Type: "github", Token: "t", Fields: map[string]string{"repo": "o/r"}},
		})
		require.NoError(t, err)
		require.Len(t, s, 2)
	})
}
