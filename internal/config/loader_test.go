package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".skret.yaml")
	content := `
version: "1"
default_env: dev
project: myproj
environments:
  dev:
    provider: local
    file: secrets.yaml
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, "1", cfg.Version)
	assert.Equal(t, "dev", cfg.DefaultEnv)
	assert.Equal(t, dir, cfg.ConfigDir)
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load("/nonexistent/.skret.yaml")
	assert.Error(t, err)
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.WriteFile(path, []byte("{{{invalid"), 0o644))

	_, err := config.Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestLoad_ValidationError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: \"2\"\n"), 0o644))

	_, err := config.Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestDiscover_FindsInCurrentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\n"), 0o644))

	found, err := config.Discover(dir)
	require.NoError(t, err)
	assert.Equal(t, path, found)
}

func TestDiscover_WalksUpToGitRoot(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, ".git"), 0o755)
	path := filepath.Join(root, ".skret.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\n"), 0o644))

	subdir := filepath.Join(root, "a", "b", "c")
	require.NoError(t, os.MkdirAll(subdir, 0o755))

	found, err := config.Discover(subdir)
	require.NoError(t, err)
	assert.Equal(t, path, found)
}

func TestDiscover_NotFound(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	_, err := config.Discover(dir)
	assert.ErrorIs(t, err, config.ErrConfigNotFound)
}

func TestDiscover_FailsRecursion(t *testing.T) {
	// Root dir check: parent == dir
	_, err := config.Discover("/")
	assert.ErrorIs(t, err, config.ErrConfigNotFound)
}
