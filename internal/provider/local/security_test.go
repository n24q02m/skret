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

	// Project dir where .skret.yaml would be
	projectDir := filepath.Join(tempDir, "project")
	require.NoError(t, os.Mkdir(projectDir, 0o700))

	t.Run("BlocksTraversalInConfig", func(t *testing.T) {
		cfg := &config.ResolvedConfig{
			File:         "../sensitive.yaml",
			FileFromFlag: false,
			ConfigDir:    projectDir,
		}

		_, err := local.New(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "escapes configuration directory")
	})

	t.Run("BlocksAbsolutePathInConfig", func(t *testing.T) {
		cfg := &config.ResolvedConfig{
			File:         "/etc/passwd",
			FileFromFlag: false,
			ConfigDir:    projectDir,
		}

		_, err := local.New(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "absolute path")
	})

	t.Run("AllowsRelativePathInConfig", func(t *testing.T) {
		secretsFile := filepath.Join(projectDir, "secrets.yaml")
		require.NoError(t, os.WriteFile(secretsFile, []byte("version: \"1\"\nsecrets: {}"), 0o600))

		cfg := &config.ResolvedConfig{
			File:         "secrets.yaml",
			FileFromFlag: false,
			ConfigDir:    projectDir,
		}

		p, err := local.New(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, p)
		p.Close()
	})

	t.Run("AllowsTrustedFlagPath", func(t *testing.T) {
		sensitiveFile := filepath.Join(tempDir, "sensitive.yaml")
		require.NoError(t, os.WriteFile(sensitiveFile, []byte("version: \"1\"\nsecrets: {}"), 0o600))

		cfg := &config.ResolvedConfig{
			File:         sensitiveFile,
			FileFromFlag: true,
			ConfigDir:    projectDir,
		}

		p, err := local.New(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, p)
		p.Close()
	})
}

func TestNew_Errors(t *testing.T) {
	t.Run("LoadError", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.yaml")
		require.NoError(t, os.WriteFile(path, []byte("{{{invalid"), 0o600))
		cfg := &config.ResolvedConfig{
			File:         path,
			FileFromFlag: true,
		}
		_, err := local.New(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "load")
	})
}

func TestNew_EdgeCases(t *testing.T) {
	t.Run("AbsoluteInConfigDir", func(t *testing.T) {
		tempDir := t.TempDir()
		projectDir := filepath.Join(tempDir, "project")
		require.NoError(t, os.Mkdir(projectDir, 0o700))

		secretsFile := filepath.Join(projectDir, "secrets.yaml")
		require.NoError(t, os.WriteFile(secretsFile, []byte("version: \"1\"\nsecrets: {}"), 0o600))

		cfg := &config.ResolvedConfig{
			File:         secretsFile,
			FileFromFlag: false,
			ConfigDir:    projectDir,
		}

		p, err := local.New(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, p)
		p.Close()
	})

	t.Run("NoConfigDir", func(t *testing.T) {
		cfg := &config.ResolvedConfig{
			File:         "secrets.yaml",
			FileFromFlag: false,
			ConfigDir:    "",
		}
		p, err := local.New(cfg)
		if err == nil {
			assert.NotNil(t, p)
			p.Close()
		}
	})
}

func TestProvider_NotSupported(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "secrets.yaml")
	cfg := &config.ResolvedConfig{
		File:         path,
		FileFromFlag: true,
	}
	p, err := local.New(cfg)
	require.NoError(t, err)
	defer p.Close()

	ctx := context.Background()
	_, err = p.GetHistory(ctx, "key")
	assert.ErrorIs(t, err, provider.ErrCapabilityNotSupported)

	err = p.Rollback(ctx, "key", 1)
	assert.ErrorIs(t, err, provider.ErrCapabilityNotSupported)
}
