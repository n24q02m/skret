package cli_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteCmd_ConfirmFlag(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	out, err := executeCmd("delete", "API_KEY", "--confirm")
	require.NoError(t, err)
	assert.Contains(t, out, "Deleted API_KEY")

	// Verify key is gone
	_, err = executeCmd("get", "API_KEY")
	assert.Error(t, err)
}

func TestDeleteCmd_ForceFlag(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	out, err := executeCmd("delete", "REDIS_URL", "-f")
	require.NoError(t, err)
	assert.Contains(t, out, "Deleted REDIS_URL")

	// Verify key is gone
	_, err = executeCmd("get", "REDIS_URL")
	assert.Error(t, err)
}

func TestDeleteCmd_PromptYes(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	r, w, _ := os.Pipe()
	os.Stdin = r
	w.Write([]byte("y\n"))
	w.Close()

	out, err := executeCmd("delete", "DATABASE_URL")
	require.NoError(t, err)
	assert.Contains(t, out, "Deleted DATABASE_URL")

	// Verify key is gone
	_, err = executeCmd("get", "DATABASE_URL")
	assert.Error(t, err)
}

func TestDeleteCmd_PromptNo(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	r, w, _ := os.Pipe()
	os.Stdin = r
	w.Write([]byte("n\n"))
	w.Close()

	out, err := executeCmd("delete", "API_KEY")
	require.NoError(t, err)
	assert.Contains(t, out, "Cancelled.")

	// Verify key still exists
	val, err := executeCmd("get", "API_KEY", "--plain")
	require.NoError(t, err)
	assert.Equal(t, "secret123", strings.TrimSpace(val))
}

func TestDeleteCmd_NonExistent(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	_, err := executeCmd("delete", "NONEXISTENT", "--confirm")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDeleteCmd_MissingArg(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	_, err := executeCmd("delete")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 1 arg")
}
