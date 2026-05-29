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

func TestLoad_Errors(t *testing.T) {
	t.Run("NotFound", func(t *testing.T) {
		_, err := config.Load("/nonexistent/.skret.yaml")
		assert.Error(t, err)
	})

	t.Run("InvalidYAML", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".skret.yaml")
		require.NoError(t, os.WriteFile(path, []byte("{{{invalid"), 0o644))
		_, err := config.Load(path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parse")
	})

	t.Run("ValidationError", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".skret.yaml")
		require.NoError(t, os.WriteFile(path, []byte("version: \"2\"\n"), 0o644))
		_, err := config.Load(path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported version")
	})

	t.Run("DirError", func(t *testing.T) {
		dir := t.TempDir()
		_, err := config.Load(dir)
		assert.Error(t, err)
	})
}

func TestDiscover(t *testing.T) {
	t.Run("FindsInCurrentDir", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".skret.yaml")
		require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\n"), 0o644))
		found, err := config.Discover(dir)
		require.NoError(t, err)
		assert.Equal(t, path, found)
	})

	t.Run("WalksUpToGitRoot", func(t *testing.T) {
		root := t.TempDir()
		_ = os.MkdirAll(filepath.Join(root, ".git"), 0o755)
		path := filepath.Join(root, ".skret.yaml")
		require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\n"), 0o644))
		subdir := filepath.Join(root, "a", "b", "c")
		require.NoError(t, os.MkdirAll(subdir, 0o755))
		found, err := config.Discover(subdir)
		require.NoError(t, err)
		assert.Equal(t, path, found)
	})

	t.Run("NotFound", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
		_, err := config.Discover(dir)
		assert.ErrorIs(t, err, config.ErrConfigNotFound)
	})

	t.Run("FailsRecursion", func(t *testing.T) {
		_, err := config.Discover("/")
		assert.ErrorIs(t, err, config.ErrConfigNotFound)
	})

	t.Run("StopsAtGitRoot", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(root, ".git"), 0o755))
		subdir := filepath.Join(root, "subdir")
		require.NoError(t, os.Mkdir(subdir, 0o755))
		_, err := config.Discover(subdir)
		assert.ErrorIs(t, err, config.ErrConfigNotFound)
	})
}
