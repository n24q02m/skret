package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRollbackCmd_Confirmation(t *testing.T) {
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
  ROLLBACK_ME: "val1"
history:
  ROLLBACK_ME:
    - version: 1
      value: val0
`), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	t.Setenv("SKRET_EXPERIMENTAL", "1")

	t.Run("confirm yes", func(t *testing.T) {
		opts := &GlobalOpts{}
		cmd := newRollbackCmd(opts)

		var stdout, stderr bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		cmd.SetIn(bytes.NewBufferString("y\n"))
		cmd.SetArgs([]string{"ROLLBACK_ME", "1"})

		err := cmd.Execute()
		require.NoError(t, err)
		assert.Contains(t, stderr.String(), "Rollback secret \"ROLLBACK_ME\" to version 1? [y/N]")
		assert.Contains(t, stderr.String(), "Successfully rolled back \"ROLLBACK_ME\" to version 1")
	})

	t.Run("confirm no", func(t *testing.T) {
		opts := &GlobalOpts{}
		cmd := newRollbackCmd(opts)

		var stdout, stderr bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		cmd.SetIn(bytes.NewBufferString("n\n"))
		cmd.SetArgs([]string{"ROLLBACK_ME", "1"})

		err := cmd.Execute()
		require.NoError(t, err)
		assert.Contains(t, stderr.String(), "Cancelled.")
	})
}

func TestRollbackCmd_Flags(t *testing.T) {
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

	t.Setenv("SKRET_EXPERIMENTAL", "1")

	t.Run("--confirm", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte(`
version: "1"
secrets:
  KEY1: "val1"
history:
  KEY1:
    - version: 1
      value: val0
`), 0o600))

		opts := &GlobalOpts{}
		cmd := newRollbackCmd(opts)
		cmd.SetArgs([]string{"KEY1", "1", "--confirm"})

		var stderr bytes.Buffer
		cmd.SetErr(&stderr)

		err := cmd.Execute()
		require.NoError(t, err)
		assert.NotContains(t, stderr.String(), "Rollback secret")
		assert.Contains(t, stderr.String(), "Successfully rolled back \"KEY1\" to version 1")
	})

	t.Run("-f force", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte(`
version: "1"
secrets:
  KEY2: "val2"
history:
  KEY2:
    - version: 1
      value: val0
`), 0o600))

		opts := &GlobalOpts{}
		cmd := newRollbackCmd(opts)
		cmd.SetArgs([]string{"KEY2", "1", "-f"})

		var stderr bytes.Buffer
		cmd.SetErr(&stderr)

		err := cmd.Execute()
		require.NoError(t, err)
		assert.NotContains(t, stderr.String(), "Rollback secret")
		assert.Contains(t, stderr.String(), "Successfully rolled back \"KEY2\" to version 1")
	})
}
