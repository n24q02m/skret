package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCmd_VersionFlag(t *testing.T) {
	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--version"})
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "skret")
}

func TestRootCmd_HelpFlag(t *testing.T) {
	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--help"})
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "secret manager")
}

// --- Test helpers ---

func setupTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)

	os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
`), 0o644)

	os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte(`
version: "1"
secrets:
  DATABASE_URL: "postgres://dev:dev@localhost/db"
  API_KEY: "secret123"
  REDIS_URL: "redis://localhost:6379"
`), 0o600)

	return dir
}

// --- Init tests ---

func TestInitCmd_CreatesConfigFile(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"init", "--provider=aws", "--path=/myapp/prod", "--region=us-east-1"})
	cmd.SetOut(os.Stdout)

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "provider: aws")
	assert.Contains(t, string(data), "/myapp/prod")
}

func TestInitCmd_AddsToGitignore(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("node_modules/\n"), 0o644)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"init", "--provider=local", "--file=./.secrets.dev.yaml"})

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	require.NoError(t, err)
	assert.Contains(t, string(data), ".secrets.*.yaml")
}

func TestInitCmd_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte("existing"), 0o644)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"init", "--provider=aws", "--path=/app/prod"})

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestInitCmd_ForceOverwrite(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte("existing"), 0o644)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"init", "--provider=aws", "--path=/app/new", "--force"})

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "/app/new")
}

// --- Get tests ---

func TestGetCmd_PlainOutput(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"get", "DATABASE_URL"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Equal(t, "postgres://dev:dev@localhost/db\n", buf.String())
}

func TestGetCmd_NotFound(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"get", "NONEXISTENT"})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- List tests ---

func TestListCmd_TableOutput(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"list"})

	err := cmd.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "API_KEY")
	assert.Contains(t, out, "DATABASE_URL")
	assert.Contains(t, out, "REDIS_URL")
}

func TestListCmd_JSONOutput(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"list", "--format=json"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "DATABASE_URL")
}

// --- Env tests ---

func TestEnvCmd_DotenvFormat(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"env"})

	err := cmd.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, `DATABASE_URL="postgres://dev:dev@localhost/db"`)
	assert.Contains(t, out, `API_KEY="secret123"`)
}

func TestEnvCmd_ExportFormat(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"env", "--format=export"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `export DATABASE_URL="postgres://dev:dev@localhost/db"`)
}

// --- Set tests ---

func TestSetCmd_BasicSet(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"set", "NEW_KEY", "new_value"})
	err := cmd.Execute()
	require.NoError(t, err)

	// Verify by reading back
	var buf bytes.Buffer
	cmd2 := cli.NewRootCmd()
	cmd2.SetOut(&buf)
	cmd2.SetArgs([]string{"get", "NEW_KEY"})
	err = cmd2.Execute()
	require.NoError(t, err)
	assert.Equal(t, "new_value\n", buf.String())
}

func TestSetCmd_MissingArgs(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"set", "KEY_ONLY"})
	err := cmd.Execute()
	assert.Error(t, err)
}

// --- Delete tests ---

func TestDeleteCmd_Success(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"delete", "API_KEY", "--confirm"})
	err := cmd.Execute()
	require.NoError(t, err)

	cmd2 := cli.NewRootCmd()
	cmd2.SetArgs([]string{"get", "API_KEY"})
	err = cmd2.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDeleteCmd_NotFound(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"delete", "NONEXISTENT", "--confirm"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- Run tests ---

func TestRunCmd_MissingCommand(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"run"})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestRunCmd_RequiredSecretMissing(t *testing.T) {
	dir := setupTestRepo(t)
	// Add required secret spec
	os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`
version: "1"
default_env: dev
required: ["MISSING_REQUIRED"]
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
`), 0o644)

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"run", "--", "go", "version"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required secret")
}

// --- Import tests ---

func TestImportCmd_Dotenv(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	envContent := `IMPORT_KEY=imported_value`
	os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0o644)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"import", "--from=dotenv", "--file=.env"})
	err := cmd.Execute()
	require.NoError(t, err)

	var buf bytes.Buffer
	cmd2 := cli.NewRootCmd()
	cmd2.SetOut(&buf)
	cmd2.SetArgs([]string{"get", "IMPORT_KEY"})
	err = cmd2.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "imported_value")
}

func TestImportCmd_ToPath(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	envContent := `IMPORT_KEY=imported_value`
	os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0o644)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"import", "--from=dotenv", "--file=.env", "--to-path=/imported/"})
	err := cmd.Execute()
	require.NoError(t, err)

	var buf bytes.Buffer
	cmd2 := cli.NewRootCmd()
	cmd2.SetOut(&buf)
	cmd2.SetArgs([]string{"get", "/imported/IMPORT_KEY"})
	err = cmd2.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "imported_value")
}

// --- Sync tests ---

func TestSyncCmd_Dotenv(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"sync", "--to=dotenv", "--file=.env.synced"})
	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, ".env.synced"))
	require.NoError(t, err)
	assert.Contains(t, string(data), `API_KEY="secret123"`)
}

// --- Additional format tests ---

func TestEnvCmd_JsonYamlFormats(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"env", "--format=json"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), `"DATABASE_URL": "postgres://`)

	buf.Reset()
	cmd2 := cli.NewRootCmd()
	cmd2.SetOut(&buf)
	cmd2.SetArgs([]string{"env", "--format=yaml"})
	require.NoError(t, cmd2.Execute())
	assert.Contains(t, buf.String(), "DATABASE_URL: postgres://")
}

func TestSetCmd_FromFile(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	os.WriteFile("val.txt", []byte("file_value"), 0o644)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"set", "FILE_KEY", "--from-file=val.txt"})
	require.NoError(t, cmd.Execute())

	var buf bytes.Buffer
	cmd2 := cli.NewRootCmd()
	cmd2.SetOut(&buf)
	cmd2.SetArgs([]string{"get", "FILE_KEY"})
	require.NoError(t, cmd2.Execute())
	assert.Contains(t, buf.String(), "file_value")
}
