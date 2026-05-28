package local_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/config"
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
