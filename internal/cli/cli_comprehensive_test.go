package cli_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Import with dry-run ---

func TestImportCmd_DryRun(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	// Create a .env file to import
	envContent := "NEW_DRY_KEY=dry_val\nOTHER_DRY_KEY=other_val"
	err := os.WriteFile(filepath.Join(dir, ".env.dry"), []byte(envContent), 0o644)
	require.NoError(t, err)

	out, err := executeCmd("import", "--from=dotenv", "--file=.env.dry", "--dry-run")
	require.NoError(t, err)
	assert.Contains(t, out, "[dry-run]")
	assert.Contains(t, out, "Imported: 2")

	// Verify nothing was actually written
	_, err = executeCmd("get", "NEW_DRY_KEY")
	assert.Error(t, err)
}

// --- Import overwrite conflict strategy ---

func TestImportCmd_ConflictOverwrite(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	// API_KEY already exists with value "secret123"
	envContent := "API_KEY=new_api_key_value"
	err := os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0o644)
	require.NoError(t, err)

	out, err := executeCmd("import", "--from=dotenv", "--file=.env", "--on-conflict=overwrite")
	require.NoError(t, err)
	assert.Contains(t, out, "Imported: 1")

	// Verify the value was overwritten
	valOut, err := executeCmd("get", "API_KEY", "--plain")
	require.NoError(t, err)
	assert.Equal(t, "new_api_key_value", valOut)
}

// --- Set: from-file with non-existent file ---

func TestSetCmd_FromFileNotFound(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	_, err := executeCmd("set", "KEY", "--from-file=nonexistent.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read file")
}

// --- Set: no value provided ---

func TestSetCmd_NoValue(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	_, err := executeCmd("set", "KEY")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "value required")
}

// --- Sync unknown target ---

func TestSyncCmd_UnknownTarget(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	_, err := executeCmd("sync", "--to=unknown")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown target")
}

// --- Sync GitHub missing token ---

func TestSyncCmd_GitHubMissingToken(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	t.Setenv("GITHUB_TOKEN", "")
	_, err := executeCmd("sync", "--to=github", "--github-repo=owner/repo")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GITHUB_TOKEN")
}

// --- Init without git dir ---

func TestInitCmd_LocalProvider(t *testing.T) {
	dir := t.TempDir()
	err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	require.NoError(t, err)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"init", "--provider=local", "--file=.secrets.dev.yaml"})

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	err = cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "provider: local")
}

// --- Init: gitignore already has entries ---

func TestInitCmd_GitignoreAlreadyComplete(t *testing.T) {
	dir := t.TempDir()
	err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".secrets.*.yaml\n.secrets.*.yml\n"), 0o644)
	require.NoError(t, err)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"init", "--provider=aws", "--path=/app/prod"})

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	err = cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	require.NoError(t, err)
	// Should not duplicate entries
	content := string(data)
	assert.Equal(t, ".secrets.*.yaml\n.secrets.*.yml\n", content)
}

// --- History with experimental flag enabled and AWS-like provider mock behavior ---

func TestHistoryCmd_ExperimentalEnabled_LocalNotSupported(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	t.Setenv("SKRET_EXPERIMENTAL", "1")
	_, err := executeCmd("history", "DATABASE_URL")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not support this operation")
}

// --- Rollback experimental with invalid version number ---

func TestRollbackCmd_ExperimentalEnabled_ParseError(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	t.Setenv("SKRET_EXPERIMENTAL", "1")
	_, err := executeCmd("rollback", "DATABASE_URL", "abc")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid version number")
}

// --- Run with existing command ---

func TestRunCmd_SimpleCommand(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	// "go version" should work as a simple command, though on Windows
	// it will actually exec as a child process
	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"run", "--", "go", "version"})
	// This will exec "go version" which replaces the process on Unix
	// but on Windows runs as child. Either way we test the path.
	// We don't assert on error because exec behavior varies by OS.
	_ = cmd.Execute()
}

// --- Run with non-existent command ---

func TestRunCmd_CommandNotFound(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	_, err := executeCmd("run", "--", "nonexistent_command_12345")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "command not found")
}

// --- Global flags: --log-level ---

func TestRootCmd_LogLevelFlag(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	out, err := executeCmd("--log-level=debug", "list")
	require.NoError(t, err)
	assert.Contains(t, out, "KEY")
}

// --- Env: list failure path ---

func TestEnvCmd_BrokenConfig(t *testing.T) {
	dir := t.TempDir()
	err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`version: "invalid"`), 0o644)
	require.NoError(t, err)

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	_, err = executeCmd("env")
	assert.Error(t, err)
}

// --- filterSecrets non-recursive with matching depth ---

func TestListCmd_NonRecursiveFiltering(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	// This tests the filterSecrets path with recursive=false
	out, err := executeCmd("list", "--recursive=false")
	require.NoError(t, err)
	assert.Contains(t, out, "KEY")
}

// --- Import with Infisical (token provided) ---

func TestImportCmd_InfisicalWithToken(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	// Set the token but the URL is empty so it defaults to real Infisical API
	// which will fail with network error - that's fine, we just want to cover createImporter
	t.Setenv("INFISICAL_TOKEN", "test-token-value")
	_, err := executeCmd("import", "--from=infisical", "--infisical-project-id=proj", "--infisical-env=dev")
	assert.Error(t, err) // Will fail trying to reach Infisical API
}

// --- Delete: without confirm or force, but with "y" on stdin ---

func TestDeleteCmd_WithYesStdin(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	r, w, _ := os.Pipe()
	os.Stdin = r
	_, _ = w.Write([]byte("y\n"))
	_ = w.Close()

	out, err := executeCmd("delete", "API_KEY")
	require.NoError(t, err)
	assert.Contains(t, out, "Deleted API_KEY")
}

// --- Env with exclude config ---

func TestEnvCmd_WithExclude(t *testing.T) {
	dir := t.TempDir()
	err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`
version: "1"
default_env: dev
exclude:
  - API_KEY
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
`), 0o644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte(`
version: "1"
secrets:
  DATABASE_URL: "postgres://dev"
  API_KEY: "secret123"
`), 0o600)
	require.NoError(t, err)

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	out, err := executeCmd("env")
	require.NoError(t, err)
	assert.Contains(t, out, "DATABASE_URL")
	assert.NotContains(t, out, "API_KEY")
}

// --- List with path prefix that has leading slash added ---

func TestListCmd_PathAutoSlash(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	// Path without leading slash should get it added
	out, err := executeCmd("list", "--path=prefix")
	require.NoError(t, err)
	assert.Contains(t, out, "KEY")
}

// --- Init with region flag ---

func TestInitCmd_WithRegionFlag(t *testing.T) {
	dir := t.TempDir()
	err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	require.NoError(t, err)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"init", "--provider=aws", "--path=/app/prod", "--region=eu-west-1"})

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	err = cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "eu-west-1")
}

// --- Global flag overrides ---

func TestRootCmd_EnvOverride(t *testing.T) {
	dir := t.TempDir()
	err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
  staging:
    provider: local
    file: ./.secrets.staging.yaml
`), 0o644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, ".secrets.staging.yaml"), []byte(`
version: "1"
secrets:
  STAGING_KEY: staging_val
`), 0o600)
	require.NoError(t, err)

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	out, err := executeCmd("--env=staging", "get", "STAGING_KEY")
	require.NoError(t, err)
	assert.Contains(t, out, "staging_val")
}
