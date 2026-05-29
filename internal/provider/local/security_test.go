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
}

func TestProvider_Operations(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "secrets.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\nsecrets: {}\n"), 0o600))
	cfg := &config.ResolvedConfig{File: path, FileFromFlag: true}
	p, err := local.New(cfg)
	require.NoError(t, err)
	defer p.Close()
	ctx := context.Background()

	t.Run("Lifecycle", func(t *testing.T) {
		err = p.Set(ctx, "key1", "val1", provider.SecretMeta{})
		assert.NoError(t, err)

		s, err := p.Get(ctx, "key1")
		assert.NoError(t, err)
		assert.Equal(t, "val1", s.Value)

		secrets, err := p.GetBatch(ctx, []string{"key1", "missing"})
		assert.NoError(t, err)
		assert.Len(t, secrets, 1)

		list, err := p.List(ctx, "")
		assert.NoError(t, err)
		assert.Len(t, list, 1)

		err = p.Delete(ctx, "key1")
		assert.NoError(t, err)

		_, err = p.Get(ctx, "key1")
		assert.ErrorIs(t, err, provider.ErrNotFound)

		err = p.Delete(ctx, "missing")
		assert.ErrorIs(t, err, provider.ErrNotFound)
	})

	t.Run("Capabilities", func(t *testing.T) {
		_ = p.Capabilities()
		assert.Equal(t, "local", p.Name())
	})

	t.Run("NotSupported", func(t *testing.T) {
		_, err := p.GetHistory(ctx, "k")
		assert.ErrorIs(t, err, provider.ErrCapabilityNotSupported)
		err = p.Rollback(ctx, "k", 1)
		assert.ErrorIs(t, err, provider.ErrCapabilityNotSupported)
	})
}

func TestSave_Errors(t *testing.T) {
	t.Run("CreateTempError", func(t *testing.T) {
		tempDir := t.TempDir()
		path := filepath.Join(tempDir, "secrets.yaml")
		require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\nsecrets: {}\n"), 0o600))
		p, _ := local.New(&config.ResolvedConfig{File: path, FileFromFlag: true})
		defer p.Close()

		require.NoError(t, os.RemoveAll(tempDir))
		require.NoError(t, os.WriteFile(tempDir, []byte("blocker"), 0o600))

		err := p.Set(context.Background(), "k", "v", provider.SecretMeta{})
		assert.Error(t, err)
	})

	t.Run("RenameError", func(t *testing.T) {
		tempDir := t.TempDir()
		path := filepath.Join(tempDir, "secrets.yaml")
		require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\nsecrets: {}\n"), 0o600))
		p, _ := local.New(&config.ResolvedConfig{File: path, FileFromFlag: true})
		defer p.Close()

		require.NoError(t, os.Remove(path))
		require.NoError(t, os.Mkdir(path, 0o700))

		err := p.Set(context.Background(), "k", "v", provider.SecretMeta{})
		assert.Error(t, err)
	})
}
