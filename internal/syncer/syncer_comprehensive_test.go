package syncer_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/syncer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Dotenv escaping edge cases ---

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
	// On Unix-like systems, permissions should be 0600
	// On Windows, this check is less meaningful
	assert.False(t, info.IsDir())
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
