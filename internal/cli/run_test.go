package cli

import (
	"errors"
	"testing"

	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRunCmd_Validation(t *testing.T) {
	opts := &GlobalOpts{}
	cmd := newRunCmd(opts)

	// Test missing command
	err := cmd.RunE(cmd, []string{})
	require.Error(t, err)
	var skretErr *skret.Error
	require.True(t, errors.As(err, &skretErr))
	assert.Equal(t, skret.ExitValidationError, skretErr.Code)
	assert.Contains(t, err.Error(), "command required")
}

func TestExecCommand(t *testing.T) {
	// Backup and restore skexecRun
	origSkexecRun := skexecRun
	defer func() { skexecRun = origSkexecRun }()

	t.Run("success", func(t *testing.T) {
		skexecRun = func(binary string, args []string, env []string) error {
			return nil
		}
		// "go" should be found on most systems
		err := execCommand([]string{"go", "version"}, []string{})
		assert.NoError(t, err)
	})

	t.Run("command not found", func(t *testing.T) {
		err := execCommand([]string{"nonexistent-command-123456789"}, []string{})
		require.Error(t, err)
		var skretErr *skret.Error
		require.True(t, errors.As(err, &skretErr))
		assert.Equal(t, skret.ExitExecError, skretErr.Code)
		assert.Contains(t, err.Error(), "command not found")
	})

	t.Run("runtime error", func(t *testing.T) {
		skexecRun = func(binary string, args []string, env []string) error {
			return errors.New("boom")
		}
		err := execCommand([]string{"go", "version"}, []string{})
		require.Error(t, err)
		var skretErr *skret.Error
		require.True(t, errors.As(err, &skretErr))
		assert.Equal(t, skret.ExitExecError, skretErr.Code)
		assert.Contains(t, err.Error(), "runtime error")
	})
}
