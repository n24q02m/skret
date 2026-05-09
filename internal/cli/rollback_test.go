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

	t.Run("confirm no", func(t *testing.T) {
		opts := &GlobalOpts{}
		cmd := newRollbackCmd(opts)

		var stdout, stderr bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		cmd.SetIn(bytes.NewBufferString("n\n"))
		cmd.SetArgs([]string{"ROLLBACK_ME", "1"})

		err := cmd.Execute()
		require.NoError(t, err) // Execution is cancelled early so this should not return the provider not supported error
		assert.Contains(t, stderr.String(), "Cancelled.")
	})
}
