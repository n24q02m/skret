package cli_test

import (
	"os"
	"testing"

	"github.com/n24q02m/skret/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRollbackCmd_Args(t *testing.T) {
	cmd := cli.NewRootCmd()

	t.Run("too few args", func(t *testing.T) {
		cmd.SetArgs([]string{"rollback", "KEY"})
		err := cmd.Execute()
		assert.Error(t, err)
	})

	t.Run("too many args", func(t *testing.T) {
		cmd.SetArgs([]string{"rollback", "KEY", "1", "extra"})
		err := cmd.Execute()
		assert.Error(t, err)
	})
}

func TestRollbackCmd_NoConfigError(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	t.Setenv("SKRET_EXPERIMENTAL", "1")

	_, err := executeCmd("rollback", "KEY", "1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "find config failed")
}
