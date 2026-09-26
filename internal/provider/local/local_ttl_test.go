package local

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/keystore"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ttlConfig builds a resolved config pointing at a temp local file.
func ttlConfig(t *testing.T) *config.ResolvedConfig {
	t.Helper()
	return &config.ResolvedConfig{
		Provider: "local",
		File:     filepath.Join(t.TempDir(), "secrets.yaml"),
	}
}

func TestTTL_PlaintextRoundTrip(t *testing.T) {
	p, err := New(ttlConfig(t))
	require.NoError(t, err)
	defer p.Close()

	expiry := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	require.NoError(t, p.Set(context.Background(), "API_KEY", "v1", provider.SecretMeta{ExpiresAt: expiry}))

	// Metadata lands in the YAML file under meta:.
	raw, err := os.ReadFile(p.(*Provider).filePath)
	require.NoError(t, err)
	var store struct {
		Meta map[string]string `yaml:"meta"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &store))
	require.Contains(t, store.Meta, "API_KEY")
	parsed, err := time.Parse(time.RFC3339, store.Meta["API_KEY"])
	require.NoError(t, err)
	assert.True(t, parsed.Equal(expiry.UTC()), "stored %v want %v", parsed, expiry.UTC())

	// Get/List surface it; keys without expiry stay zero.
	s, err := p.Get(context.Background(), "API_KEY")
	require.NoError(t, err)
	assert.True(t, s.Meta.ExpiresAt.Equal(expiry.UTC()))
	require.NoError(t, p.Set(context.Background(), "DB_PASS", "v2", provider.SecretMeta{}))
	list, err := p.List(context.Background(), "")
	require.NoError(t, err)
	for _, item := range list {
		if item.Key == "DB_PASS" {
			assert.True(t, item.Meta.ExpiresAt.IsZero())
		}
	}

	// A fresh provider instance reads the same metadata (round trip).
	p2, err := New(ttlConfigFor(t, p.(*Provider).filePath))
	require.NoError(t, err)
	defer p2.Close()
	s2, err := p2.Get(context.Background(), "API_KEY")
	require.NoError(t, err)
	assert.True(t, s2.Meta.ExpiresAt.Equal(expiry.UTC()), "expiry must survive reopen")
}

// ttlConfigFor points a config at an existing secrets file.
func ttlConfigFor(t *testing.T, path string) *config.ResolvedConfig {
	t.Helper()
	return &config.ResolvedConfig{Provider: "local", File: path}
}

func TestTTL_SetWithoutTTLPreservesExisting(t *testing.T) {
	p, err := New(ttlConfig(t))
	require.NoError(t, err)
	defer p.Close()

	expiry := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	require.NoError(t, p.Set(context.Background(), "K", "v1", provider.SecretMeta{ExpiresAt: expiry}))
	// Overwrite value with zero ExpiresAt: expiry must survive.
	require.NoError(t, p.Set(context.Background(), "K", "v2", provider.SecretMeta{}))

	s, err := p.Get(context.Background(), "K")
	require.NoError(t, err)
	assert.Equal(t, "v2", s.Value)
	assert.True(t, s.Meta.ExpiresAt.Equal(expiry.UTC()), "expiry must survive plain set")
}

func TestTTL_EncryptedFileRoundTrip(t *testing.T) {
	cfg := ttlConfig(t)
	cfg.Encrypted = true
	t.Setenv(keystore.EnvKeyPrimary, "test-key-material")
	p, err := New(cfg)
	require.NoError(t, err)
	defer p.Close()
	prov := p.(*Provider)

	expiry := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	require.NoError(t, p.Set(context.Background(), "API_KEY", "v1", provider.SecretMeta{ExpiresAt: expiry}))
	require.NoError(t, p.Set(context.Background(), "PLAIN", "v2", provider.SecretMeta{}))

	raw, err := os.ReadFile(prov.filePath)
	require.NoError(t, err)
	require.True(t, keystore.Detect(raw), "file must stay an encrypted envelope")

	// Reopen with the same key material: secrets and expiry both survive.
	p2, err := New(ttlConfigFor(t, prov.filePath))
	require.NoError(t, err)
	defer p2.Close()
	s, err := p2.Get(context.Background(), "API_KEY")
	require.NoError(t, err)
	assert.Equal(t, "v1", s.Value)
	assert.True(t, s.Meta.ExpiresAt.Equal(expiry.UTC()), "expiry must survive the encrypted path")
}

// TestTTL_MalformedMetaIgnored: a malformed expiry entry is ignored on reads
// (never fails them) while well-formed entries still surface — through Get
// and GetBatch alike, and keys absent from the batch result stay absent.
func TestTTL_MalformedMetaIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.yaml")
	expiry := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	body := "version: \"1\"\n" +
		"secrets:\n" +
		"  BAD_META: v1\n" +
		"  GOOD_META: v2\n" +
		"meta:\n" +
		"  BAD_META: not-a-timestamp\n" +
		"  GOOD_META: " + expiry.Format(time.RFC3339) + "\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	p, err := New(ttlConfigFor(t, path))
	require.NoError(t, err)
	defer p.Close()

	s, err := p.Get(context.Background(), "BAD_META")
	require.NoError(t, err)
	assert.True(t, s.Meta.ExpiresAt.IsZero(), "malformed expiry must be ignored, not surfaced")

	batch, err := p.GetBatch(context.Background(), []string{"BAD_META", "GOOD_META", "MISSING"})
	require.NoError(t, err)
	require.Len(t, batch, 2)
	byKey := make(map[string]provider.Secret, len(batch))
	for _, item := range batch {
		byKey[item.Key] = *item
	}
	assert.True(t, byKey["BAD_META"].Meta.ExpiresAt.IsZero())
	assert.True(t, byKey["GOOD_META"].Meta.ExpiresAt.Equal(expiry), "valid expiry must surface through GetBatch")
}
