package cli_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistoryCmd_ExperimentalGate(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	// Without SKRET_EXPERIMENTAL, should be blocked
	t.Setenv("SKRET_EXPERIMENTAL", "")
	_, err := executeCmd("history", "DATABASE_URL")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "experimental")

	// With SKRET_EXPERIMENTAL=0, should still be blocked
	t.Setenv("SKRET_EXPERIMENTAL", "0")
	_, err = executeCmd("history", "DATABASE_URL")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "experimental")
}

func TestRollbackCmd_ExperimentalGate(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	// Without SKRET_EXPERIMENTAL, should be blocked
	t.Setenv("SKRET_EXPERIMENTAL", "")
	_, err := executeCmd("rollback", "DATABASE_URL", "1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "experimental")
}

func TestHistoryCmd_NotSupported(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	// Enable experimental flag, then test local provider does not support history
	t.Setenv("SKRET_EXPERIMENTAL", "1")
	_, err := executeCmd("history", "DATABASE_URL")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not support this operation")
}

func TestRollbackCmd_NotSupported(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	// Enable experimental flag, then test local provider does not support rollback.
	// --force skips the confirmation prompt so this exercises the provider path.
	t.Setenv("SKRET_EXPERIMENTAL", "1")
	_, err := executeCmd("rollback", "DATABASE_URL", "1", "--force")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not support this operation")
}

func TestRollbackCmd_ConfirmCancel(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	// No --force and no "y" on stdin -> confirmation declined, no rollback,
	// no error (rollback is destructive; default is to cancel).
	t.Setenv("SKRET_EXPERIMENTAL", "1")
	out, err := executeCmd("rollback", "DATABASE_URL", "1")
	assert.NoError(t, err)
	assert.Contains(t, out, "Cancelled")
}

func TestRollbackCmd_InvalidVersion(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	// Enable experimental flag to test past the gate
	t.Setenv("SKRET_EXPERIMENTAL", "1")
	_, err := executeCmd("rollback", "DATABASE_URL", "not-a-number")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid version number")
}
