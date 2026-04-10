package cli_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestRepo is reused from cli_test.go

func executeCmd(args ...string) (string, error) {
	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestCLI_EdgeCases(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	// 1. Get: JSON output
	out, err := executeCmd("get", "DATABASE_URL", "--json")
	require.NoError(t, err)
	assert.Contains(t, out, `"key": "DATABASE_URL"`)

	// 2. Get: Plain output
	out, err = executeCmd("get", "DATABASE_URL", "--plain")
	require.NoError(t, err)
	assert.Equal(t, "postgres://dev:dev@localhost/db", out)

	// 3. Set: With tags and description
	_, err = executeCmd("set", "TAG_KEY", "val", "-d", "desc", "-t", "env=prod")
	require.NoError(t, err)
	// Local provider does not store metadata so we only ensure command parses

	// 4. Set: error on missing value
	_, err = executeCmd("set", "TAG_KEY")
	assert.Error(t, err)

	// 5. Delete: No confirmation fallback test via error or cancel
	// Can't easily test prompt without stdin mock, so we test confirm flag
	_, err = executeCmd("delete", "DATABASE_URL", "--confirm")
	require.NoError(t, err)
	_, err = executeCmd("get", "DATABASE_URL")
	assert.Error(t, err)

	// 6. List: Path override and non-recursive
	_, err = executeCmd("list", "--path=/prefix", "--recursive=false")
	// Since local provider ignores path physically, it just returns them
	require.NoError(t, err)

	// 7. Import: unknown source
	_, err = executeCmd("import", "--from=unknown")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown source")

	// 8. Import: doppler error missing config
	_, err = executeCmd("import", "--from=doppler")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "DOPPLER_TOKEN")

	// 9. Sync: github error missing repo
	os.Setenv("GITHUB_TOKEN", "dummy")
	defer os.Unsetenv("GITHUB_TOKEN")

	_, err = executeCmd("sync", "--to=github")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires at least one repository")

	// 9b. Sync: github error missing token (results in 401 or 404 from GitHub depending on the "dummy" token)
	_, err = executeCmd("sync", "--to=github", "--github-repo=owner/repo")
	assert.Error(t, err)
	// GitHub might return 401 for "dummy" token instead of 404
	assert.True(t, strings.Contains(err.Error(), "API returned 404") || strings.Contains(err.Error(), "API returned 401"))

	// 10. Sync: github error invalid format
	_, err = executeCmd("sync", "--to=github", "--github-repo=invalidrepo")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid repo format")

	// 11. Helpers failure: broken config
	os.WriteFile(".skret.yaml", []byte(`version: "invalid"`), 0o644)
	_, err = executeCmd("list")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "load config failed")

	// 12. Helpers missing config
	os.Remove(".skret.yaml")
	_, err = executeCmd("list")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "find config failed")
}

func TestDeleteCmd_Cancel(t *testing.T) {
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
}

func TestSetCmd_FromStdin(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	r, w, _ := os.Pipe()
	os.Stdin = r
	w.Write([]byte("stdin_value\n"))
	w.Close()

	_, err := executeCmd("set", "STDIN_KEY", "--from-stdin")
	require.NoError(t, err)

	out, err := executeCmd("get", "STDIN_KEY", "--plain")
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(out), "stdin_value")
}
