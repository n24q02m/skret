package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteCmd_Confirmation(t *testing.T) {
	// Setup test environment
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte(`
version: "1"
secrets:
  DELETE_ME: "killme"
`), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	t.Run("confirm yes", func(t *testing.T) {
		opts := &GlobalOpts{}
		cmd := newDeleteCmd(opts)

		var stdout, stderr bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		cmd.SetIn(bytes.NewBufferString("y\n"))
		cmd.SetArgs([]string{"DELETE_ME"})

		err := cmd.Execute()
		require.NoError(t, err)
		assert.Contains(t, stderr.String(), "Delete secret \"DELETE_ME\"? [y/N]")
		assert.Contains(t, stderr.String(), "Deleted DELETE_ME")
	})

	t.Run("confirm no", func(t *testing.T) {
		// Reset secrets file
		require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte(`
version: "1"
secrets:
  DELETE_ME: "killme"
`), 0o600))

		opts := &GlobalOpts{}
		cmd := newDeleteCmd(opts)

		var stdout, stderr bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		cmd.SetIn(bytes.NewBufferString("n\n"))
		cmd.SetArgs([]string{"DELETE_ME"})

		err := cmd.Execute()
		require.NoError(t, err)
		assert.Contains(t, stderr.String(), "Cancelled.")

		// Verify still exists
		data, _ := os.ReadFile(filepath.Join(dir, "secrets.yaml"))
		assert.Contains(t, string(data), "DELETE_ME")
	})
}

func TestDeleteCmd_Flags(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./secrets.yaml
`), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	t.Run("--confirm", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte(`
version: "1"
secrets:
  KEY1: "val1"
`), 0o600))

		opts := &GlobalOpts{}
		cmd := newDeleteCmd(opts)
		cmd.SetArgs([]string{"KEY1", "--confirm"})

		var stderr bytes.Buffer
		cmd.SetErr(&stderr)

		err := cmd.Execute()
		require.NoError(t, err)
		assert.NotContains(t, stderr.String(), "Delete secret")
		assert.Contains(t, stderr.String(), "Deleted KEY1")
	})

	t.Run("-f force", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte(`
version: "1"
secrets:
  KEY2: "val2"
`), 0o600))

		opts := &GlobalOpts{}
		cmd := newDeleteCmd(opts)
		cmd.SetArgs([]string{"KEY2", "-f"})

		var stderr bytes.Buffer
		cmd.SetErr(&stderr)

		err := cmd.Execute()
		require.NoError(t, err)
		assert.NotContains(t, stderr.String(), "Delete secret")
		assert.Contains(t, stderr.String(), "Deleted KEY2")
	})
}

func TestDeleteCmd_NotFound_ExitCodeAndHint(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte("version: \"1\"\nsecrets: {}"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	opts := &GlobalOpts{}
	cmd := newDeleteCmd(opts)
	cmd.SetArgs([]string{"NOPE", "--confirm"})

	err := cmd.Execute()
	require.Error(t, err)

	var se *skret.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, skret.ExitNotFoundError, se.Code)
	assert.Contains(t, se.Message, "Nothing to delete")
	assert.Contains(t, se.Message, "skret history NOPE")
}
