package cli_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistoryCmd_NotSupported(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	out, err := executeCmd("history", "DATABASE_URL")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not support this operation")
	assert.Empty(t, out)
}

func TestRollbackCmd_NotSupported(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	out, err := executeCmd("rollback", "DATABASE_URL", "1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not support this operation")
	assert.Empty(t, out)
}

func TestRollbackCmd_InvalidVersion(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	_, err := executeCmd("rollback", "DATABASE_URL", "not-a-number")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid version number")
}
