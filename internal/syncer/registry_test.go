package syncer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistry_Build(t *testing.T) {
	t.Run("unknown type", func(t *testing.T) {
		_, err := Build([]TargetConfig{{Type: "vault"}})
		require.ErrorContains(t, err, `sync target 0: unknown type "vault"`)
	})
	t.Run("unknown type at non-zero index", func(t *testing.T) {
		_, err := Build([]TargetConfig{
			{Type: "dotenv", Fields: map[string]string{}},
			{Type: "vault"},
		})
		require.ErrorContains(t, err, `sync target 1: unknown type "vault"`)
	})
	t.Run("factory error reports index", func(t *testing.T) {
		_, err := Build([]TargetConfig{
			{Type: "dotenv", Fields: map[string]string{}},
			{Type: "github", Token: "t", Fields: map[string]string{}},
		})
		require.ErrorContains(t, err, "sync target 1 (github)")
		require.ErrorContains(t, err, "repo")
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
	t.Run("github malformed repo", func(t *testing.T) {
		_, err := Build([]TargetConfig{{Type: "github", Token: "t", Fields: map[string]string{"repo": "invalidrepo"}}})
		require.ErrorContains(t, err, "must be owner/repo")
	})
}

func TestRegistry_Cloudflare(t *testing.T) {
	t.Run("worker needs account+token", func(t *testing.T) {
		_, err := Build([]TargetConfig{{Type: "cloudflare", Fields: map[string]string{"worker": "w"}}})
		require.ErrorContains(t, err, "account")
	})
	t.Run("valid worker", func(t *testing.T) {
		s, err := Build([]TargetConfig{{Type: "cloudflare", Token: "t", Fields: map[string]string{"worker": "w", "account": "a"}}})
		require.NoError(t, err)
		assert.Equal(t, "cloudflare", s[0].Name())
	})
	t.Run("missing worker and pages", func(t *testing.T) {
		_, err := Build([]TargetConfig{{Type: "cloudflare", Token: "t", Fields: map[string]string{"account": "a"}}})
		require.ErrorContains(t, err, "worker or pages")
	})
	t.Run("missing token", func(t *testing.T) {
		_, err := Build([]TargetConfig{{Type: "cloudflare", Fields: map[string]string{"worker": "w", "account": "a"}}})
		require.ErrorContains(t, err, "CLOUDFLARE_API_TOKEN")
	})
	t.Run("valid pages", func(t *testing.T) {
		s, err := Build([]TargetConfig{{Type: "cloudflare", Token: "t", Fields: map[string]string{"pages": "p", "account": "a"}}})
		require.NoError(t, err)
		assert.Equal(t, "cloudflare", s[0].Name())
	})
}
