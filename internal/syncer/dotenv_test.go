package syncer_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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
	assert.Contains(t, content, `API_KEY="sk-123"`)
	assert.Contains(t, content, `DB_URL="postgres://host"`)
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
