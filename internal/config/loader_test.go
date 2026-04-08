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
	cfgPath := filepath.Join(dir, ".skret.yaml")
	err := os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: prod
project: testapp
environments:
  prod:
    provider: aws
    path: /testapp/prod
    region: us-east-1
`), 0o644)
	require.NoError(t, err)

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "testapp", cfg.Project)
	assert.Equal(t, "prod", cfg.DefaultEnv)
	assert.Equal(t, "aws", cfg.Environments["prod"].Provider)
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "nonexistent", ".skret.yaml"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	err := os.WriteFile(cfgPath, []byte(`invalid: [yaml: bad`), 0o644)
	require.NoError(t, err)

	_, err = config.Load(cfgPath)
	assert.Error(t, err)
}

func TestLoad_ValidationError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	err := os.WriteFile(cfgPath, []byte(`version: "1"`), 0o644)
	require.NoError(t, err)

	_, err = config.Load(cfgPath)
	assert.ErrorContains(t, err, "environments")
}

func TestDiscover_FindsInCurrentDir(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	err := os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
`), 0o644)
	require.NoError(t, err)

	found, err := config.Discover(dir)
	require.NoError(t, err)
	assert.Equal(t, cfgPath, found)
}

func TestDiscover_WalksUpToGitRoot(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, ".git"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "apps", "api"), 0o755)
	cfgPath := filepath.Join(root, ".skret.yaml")
	err := os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
`), 0o644)
	require.NoError(t, err)

	found, err := config.Discover(filepath.Join(root, "apps", "api"))
	require.NoError(t, err)
	assert.Equal(t, cfgPath, found)
}

func TestDiscover_NotFound(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	_, err := config.Discover(dir)
	assert.ErrorIs(t, err, config.ErrConfigNotFound)
}
