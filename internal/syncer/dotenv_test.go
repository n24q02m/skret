package syncer_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/importer"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/syncer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDotenvSyncer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.synced")

	secrets := []*provider.Secret{
		{Key: "DB_URL", Value: "postgres://host"},
		{Key: "API_KEY", Value: "sk-123"},
	}

	s := syncer.NewDotenv(path)
	assert.Equal(t, "dotenv", s.Name())

	err := s.Sync(context.Background(), secrets)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)
	// Safe values are emitted bare (no redundant quoting).
	assert.Contains(t, content, "API_KEY=sk-123")
	assert.Contains(t, content, "DB_URL=postgres://host")
}

// TestDotenvSyncer_RoundTrip is the regression for the sync/import asymmetry:
// values with special chars must survive sync -> import byte-for-byte.
func TestDotenvSyncer_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.rt")

	secrets := []*provider.Secret{
		{Key: "BCRYPT", Value: "$2a$14$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"},
		{Key: "PGURL", Value: "postgres://u:p$word@host/db"},
		{Key: "BACKSLASH", Value: `a\b`},
		{Key: "QUOTE", Value: `a"b`},
		{Key: "MULTILINE", Value: "line1\nline2"},
		{Key: "TABVAL", Value: "a\tb"},
		{Key: "TRAILING", Value: "secret "},
	}
	require.NoError(t, syncer.NewDotenv(path).Sync(context.Background(), secrets))

	got, err := importer.NewDotenv(path).Import(context.Background())
	require.NoError(t, err)
	m := make(map[string]string, len(got))
	for _, s := range got {
		m[s.Key] = s.Value
	}
	for _, s := range secrets {
		assert.Equal(t, s.Value, m[s.Key], "round-trip mismatch for %s", s.Key)
	}
}

// TestDotenvSyncer_NestedKeys is the regression for #536: a provider that
// lists secrets under nested paths (AWS SSM) yields keys like
// "/app/prod/db/PASSWORD". The written variable name must be the target-side
// SecretName (last path segment) -- the same name `sync --dry-run` prints --
// not the raw nested key, which is not a valid dotenv variable name.
func TestDotenvSyncer_NestedKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.nested")

	secrets := []*provider.Secret{
		{Key: "/app/prod/db/PASSWORD", Value: "nested-key-fixture-not-a-secret"},
		{Key: "/app/prod/API_KEY", Value: "sk-123"},
	}

	require.NoError(t, syncer.NewDotenv(path).Sync(context.Background(), secrets))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)

	assert.Contains(t, content, "PASSWORD=nested-key-fixture-not-a-secret")
	assert.Contains(t, content, "API_KEY=sk-123")
	assert.NotContains(t, content, "/app/prod", "raw nested key must not leak into the .env line")
}

// TestDotenvSyncer_NestedKeyCollision covers the collision edge case: two
// distinct nested keys whose last path segment is identical would produce two
// lines with the same variable name, silently losing one secret. The sync must
// fail loudly, naming both keys (never their values), and leave no file behind.
func TestDotenvSyncer_NestedKeyCollision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.collision")

	secrets := []*provider.Secret{
		{Key: "/app/prod/db/HOST", Value: "db.internal"},
		{Key: "/app/prod/cache/HOST", Value: "cache.internal"},
	}

	err := syncer.NewDotenv(path).Sync(context.Background(), secrets)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HOST")
	assert.Contains(t, err.Error(), "/app/prod/db/HOST")
	assert.Contains(t, err.Error(), "/app/prod/cache/HOST")
	assert.NotContains(t, err.Error(), "db.internal", "secret values must never appear in errors")
	assert.NotContains(t, err.Error(), "cache.internal", "secret values must never appear in errors")

	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "no file must be written when a collision is detected")
}

func TestDotenvSyncer_WriteError(t *testing.T) {
	dir := t.TempDir()
	// Using a directory path instead of a file path will cause os.WriteFile to fail
	s := syncer.NewDotenv(dir)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "key", Value: "val"}})
	assert.Error(t, err)
}

func TestDotenvSyncer_CreateTempError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "nonexistent", "inner", ".env")
	s := syncer.NewDotenv(target)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "K", Value: "V"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create temp")
}

func TestDotenvSyncer_RenameError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	s := syncer.NewDotenv(target)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "K", Value: "V"}})
	assert.Error(t, err)
}

func TestDotenvSyncer_EmptySecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.empty")

	s := syncer.NewDotenv(path)
	err := s.Sync(context.Background(), nil)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Empty(t, string(data))
}

func TestDotenvSyncer_DollarSignValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.dollar")

	secrets := []*provider.Secret{
		{Key: "PATH_VAR", Value: "$HOME/bin:$PATH"},
	}

	s := syncer.NewDotenv(path)
	err := s.Sync(context.Background(), secrets)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "PATH_VAR=")
}

func TestDotenvSyncer_EscapingEdgeCases(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.escaped")

	secrets := []*provider.Secret{
		{Key: "QUOTES", Value: `value with "quotes"`},
		{Key: "NEWLINES", Value: "line1\nline2"},
		{Key: "BACKSLASH", Value: `path\to\file`},
		{Key: "EMPTY", Value: ""},
		{Key: "SPACES", Value: "  has spaces  "},
		{Key: "UNICODE", Value: "test value unicode"},
		{Key: "EQUALS", Value: "key=value"},
	}

	s := syncer.NewDotenv(path)
	err := s.Sync(context.Background(), secrets)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)

	// All values should be quoted with %q format
	assert.Contains(t, content, `BACKSLASH=`)
	assert.Contains(t, content, `EMPTY=""`)
	assert.Contains(t, content, `EQUALS="key=value"`)
	assert.Contains(t, content, `NEWLINES=`)
	assert.Contains(t, content, `QUOTES=`)
}

func TestDotenvSyncer_Sorted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.sorted")

	secrets := []*provider.Secret{
		{Key: "Z_KEY", Value: "z"},
		{Key: "A_KEY", Value: "a"},
		{Key: "M_KEY", Value: "m"},
	}

	s := syncer.NewDotenv(path)
	err := s.Sync(context.Background(), secrets)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 3)
	assert.True(t, strings.HasPrefix(lines[0], "A_KEY="))
	assert.True(t, strings.HasPrefix(lines[1], "M_KEY="))
	assert.True(t, strings.HasPrefix(lines[2], "Z_KEY="))
}

func TestDotenvSyncer_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.perms")

	secrets := []*provider.Secret{
		{Key: "KEY", Value: "val"},
	}

	s := syncer.NewDotenv(path)
	err := s.Sync(context.Background(), secrets)
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.False(t, info.IsDir())

	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestDotenvSyncer_LargeSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.large")

	secrets := make([]*provider.Secret, 100)
	for i := 0; i < 100; i++ {
		secrets[i] = &provider.Secret{
			Key:   "KEY_" + strings.Repeat("X", 10),
			Value: strings.Repeat("V", 1000),
		}
	}

	s := syncer.NewDotenv(path)
	err := s.Sync(context.Background(), secrets)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, len(data) > 100000)
}
