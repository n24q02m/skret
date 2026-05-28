package local_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/provider/local"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathTraversalProtection(t *testing.T) {
	tempDir := t.TempDir()
	projectDir := filepath.Join(tempDir, "project")
	require.NoError(t, os.Mkdir(projectDir, 0o700))

	t.Run("BlocksTraversalInConfig", func(t *testing.T) {
		cfg := &config.ResolvedConfig{
			File:         ".." + string(filepath.Separator) + "sensitive.yaml",
			FileFromFlag: false,
			ConfigDir:    projectDir,
		}
		_, err := local.New(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "escapes configuration directory")
	})

	t.Run("BlocksAbsoluteOutsideInConfig", func(t *testing.T) {
		absOutside := filepath.Join(tempDir, "outside.yaml")
		cfg := &config.ResolvedConfig{
			File:         absOutside,
			FileFromFlag: false,
			ConfigDir:    projectDir,
		}
		_, err := local.New(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "escapes configuration directory")
	})

	t.Run("AllowsRelativeInConfigDir", func(t *testing.T) {
		secretsFile := filepath.Join(projectDir, "secrets.yaml")
		require.NoError(t, os.WriteFile(secretsFile, []byte("version: \"1\"\nsecrets: {}"), 0o600))
		cfg := &config.ResolvedConfig{
			File:         "secrets.yaml",
			FileFromFlag: false,
			ConfigDir:    projectDir,
		}
		p, err := local.New(cfg)
		require.NoError(t, err)
		require.NotNil(t, p)
		p.Close()
	})

	t.Run("AllowsAbsoluteInConfigDir", func(t *testing.T) {
		secretsFile := filepath.Join(projectDir, "secrets.yaml")
		require.NoError(t, os.WriteFile(secretsFile, []byte("version: \"1\"\nsecrets: {}"), 0o600))
		cfg := &config.ResolvedConfig{
			File:         secretsFile,
			FileFromFlag: false,
			ConfigDir:    projectDir,
		}
		p, err := local.New(cfg)
		require.NoError(t, err)
		require.NotNil(t, p)
		p.Close()
	})
}

func TestNew_Errors(t *testing.T) {
	t.Run("ReadError", func(t *testing.T) {
		dir := t.TempDir()
		cfg := &config.ResolvedConfig{
			File:         dir,
			FileFromFlag: true,
		}
		_, err := local.New(cfg)
		require.Error(t, err)
	})

	t.Run("UnmarshalError", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "invalid.yaml")
		require.NoError(t, os.WriteFile(path, []byte("secrets: [unclosed"), 0o600))
		cfg := &config.ResolvedConfig{
			File:         path,
			FileFromFlag: true,
		}
		_, err := local.New(cfg)
		require.Error(t, err)
	})

	t.Run("AbsError", func(t *testing.T) {
		oldWd, _ := os.Getwd()
		defer os.Chdir(oldWd)
		dir := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(dir, "sub"), 0o700))
		require.NoError(t, os.Chdir(filepath.Join(dir, "sub")))
		require.NoError(t, os.RemoveAll(dir))
		cfg := &config.ResolvedConfig{
			File:         "rel.yaml",
			FileFromFlag: true,
		}
		_, err := local.New(cfg)
		assert.Error(t, err)
	})

	t.Run("ConfigAbsDirError", func(t *testing.T) {
		oldWd, _ := os.Getwd()
		defer os.Chdir(oldWd)
		dir := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(dir, "sub"), 0o700))
		require.NoError(t, os.Chdir(filepath.Join(dir, "sub")))
		require.NoError(t, os.RemoveAll(dir))
		cfg := &config.ResolvedConfig{
			File:         "secrets.yaml",
			FileFromFlag: false,
			ConfigDir:    ".",
		}
		_, err := local.New(cfg)
		assert.Error(t, err)
	})
}

func TestProvider_BatchAndList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\nsecrets: {}\n"), 0o600))
	cfg := &config.ResolvedConfig{File: path, FileFromFlag: true}
	p, err := local.New(cfg)
	require.NoError(t, err)
	defer p.Close()
	ctx := context.Background()

	_ = p.Set(ctx, "k1", "v1", provider.SecretMeta{})

	t.Run("GetBatchFoundAndMissing", func(t *testing.T) {
		secrets, err := p.GetBatch(ctx, []string{"k1", "missing"})
		assert.NoError(t, err)
		assert.Len(t, secrets, 1)
	})

	t.Run("GetBatchEmptyKeys", func(t *testing.T) {
		secrets, err := p.GetBatch(ctx, []string{})
		assert.NoError(t, err)
		assert.Len(t, secrets, 0)
	})

	t.Run("List", func(t *testing.T) {
		secrets, err := p.List(ctx, "")
		assert.NoError(t, err)
		assert.Len(t, secrets, 1)
	})
}
