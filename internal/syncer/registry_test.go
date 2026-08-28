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

func TestCanonicalTargetIdentity(t *testing.T) {
	t.Run("github canonicalizes case and owner scope", func(t *testing.T) {
		a, err := CanonicalTargetIdentity(TargetConfig{
			Type:   "github",
			Fields: map[string]string{"repo": "Owner/Repo"},
		})
		require.NoError(t, err)
		b, err := CanonicalTargetIdentity(TargetConfig{
			Type:   "github",
			Fields: map[string]string{"repo": "owner/repo"},
		})
		require.NoError(t, err)
		assert.Equal(t, a, b)
	})

	t.Run("github canonicalizes equivalent base URLs", func(t *testing.T) {
		a, err := CanonicalTargetIdentity(TargetConfig{
			Type:   "github",
			Fields: map[string]string{"repo": "owner/repo", "base_url": "https://git.example/"},
		})
		require.NoError(t, err)
		b, err := CanonicalTargetIdentity(TargetConfig{
			Type:   "github",
			Fields: map[string]string{"repo": "owner/repo", "base_url": "HTTPS://GIT.EXAMPLE"},
		})
		require.NoError(t, err)
		assert.Equal(t, a, b)
	})

	t.Run("cloudflare canonicalizes endpoint in identity", func(t *testing.T) {
		a, err := CanonicalTargetIdentity(TargetConfig{
			Type:   "cloudflare",
			Fields: map[string]string{"account": "acct", "worker": "vault", "base_url": "https://cf.example/"},
		})
		require.NoError(t, err)
		b, err := CanonicalTargetIdentity(TargetConfig{
			Type:   "cloudflare",
			Fields: map[string]string{"account": "ACCT", "worker": "VAULT", "base_url": "HTTPS://CF.EXAMPLE"},
		})
		require.NoError(t, err)
		assert.Equal(t, a, b)
	})

	t.Run("endpoint path case remains significant", func(t *testing.T) {
		upper, err := CanonicalTargetIdentity(TargetConfig{
			Type:   "cloudflare",
			Fields: map[string]string{"account": "acct", "worker": "vault", "base_url": "https://cf.example/API"},
		})
		require.NoError(t, err)
		lower, err := CanonicalTargetIdentity(TargetConfig{
			Type:   "cloudflare",
			Fields: map[string]string{"account": "acct", "worker": "vault", "base_url": "https://cf.example/api"},
		})
		require.NoError(t, err)
		assert.NotEqual(t, upper, lower)
	})

	t.Run("endpoint hostname NFC is canonical", func(t *testing.T) {
		composed, err := CanonicalTargetIdentity(TargetConfig{
			Type:   "cloudflare",
			Fields: map[string]string{"account": "acct", "worker": "vault", "base_url": "https://exämple.test"},
		})
		require.NoError(t, err)
		decomposed, err := CanonicalTargetIdentity(TargetConfig{
			Type:   "cloudflare",
			Fields: map[string]string{"account": "acct", "worker": "vault", "base_url": "https://exa\u0308mple.test"},
		})
		require.NoError(t, err)
		assert.Equal(t, composed, decomposed)
	})

	t.Run("cloudflare includes account and resource kind", func(t *testing.T) {
		worker, err := CanonicalTargetIdentity(TargetConfig{
			Type:   "cloudflare",
			Fields: map[string]string{"account": "Acct", "worker": "Vault"},
		})
		require.NoError(t, err)
		pages, err := CanonicalTargetIdentity(TargetConfig{
			Type:   "cloudflare",
			Fields: map[string]string{"account": "acct", "pages": "vault"},
		})
		require.NoError(t, err)
		assert.NotEqual(t, worker, pages)
	})

	t.Run("duplicate identities fail before build", func(t *testing.T) {
		err := ValidateTargetIdentities([]TargetConfig{
			{Type: "github", Fields: map[string]string{"repo": "Owner/Repo"}},
			{Type: "github", Fields: map[string]string{"repo": "owner/repo"}},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "collision")
		assert.Contains(t, err.Error(), "github")
	})
}
