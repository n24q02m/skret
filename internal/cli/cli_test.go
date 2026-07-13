package cli_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/n24q02m/skret/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCmd_VersionFlag(t *testing.T) {
	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--version"})
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "skret")
}

func TestRootCmd_VersionFlag_NoDoublePrefix(t *testing.T) {
	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--version"})
	require.NoError(t, cmd.Execute())
	assert.NotContains(t, buf.String(), "skret version skret")
	assert.Contains(t, buf.String(), "skret version 0.0.0-dev")
}

func TestRootCmd_HelpFlag(t *testing.T) {
	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
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
	cmd.SetErr(&buf)
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
	cmd.SetErr(&buf)
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
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"list", "--format=json"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "DATABASE_URL")
}

func TestListCmd_TableOutputValues(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"list", "--values"})

	err := cmd.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "KEY")
	assert.Contains(t, out, "VERSION")
	assert.Contains(t, out, "VALUE")
}

func TestListCmd_EmptyState(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var stderrBuf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetErr(&stderrBuf)
	cmd.SetArgs([]string{"list", "--recursive=false", "--path=/nonexistent/"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, stderrBuf.String(), "No secrets found. Use 'skret set' to add a secret.")
}

func TestListCmd_EmptyStateJSON(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&stdoutBuf)
	cmd.SetErr(&stderrBuf)
	cmd.SetArgs([]string{"list", "--recursive=false", "--path=/nonexistent/", "--format=json"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Equal(t, "[]\n", stdoutBuf.String())
	assert.Contains(t, stderrBuf.String(), "No secrets found. Use 'skret set' to add a secret.")
}

// TestEnvCmd_EmptyStateJSONYAML verifies that with no secrets the env command
// still emits a valid empty structure on stdout for machine-readable formats
// while routing the human hint to stderr, so scripts parsing the output keep
// working.
func TestEnvCmd_EmptyStateJSONYAML(t *testing.T) {
	for _, tc := range []struct {
		format  string
		wantOut string
	}{
		{"json", "{}\n"},
		{"yaml", "{}\n"},
		{"dotenv", ""},
	} {
		t.Run(tc.format, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
`), 0o644))
			require.NoError(t, os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte(`
version: "1"
secrets: {}
`), 0o600))
			origDir, _ := os.Getwd()
			require.NoError(t, os.Chdir(dir))
			defer os.Chdir(origDir)

			var stdoutBuf, stderrBuf bytes.Buffer
			cmd := cli.NewRootCmd()
			cmd.SetOut(&stdoutBuf)
			cmd.SetErr(&stderrBuf)
			cmd.SetArgs([]string{"env", "--format=" + tc.format})

			require.NoError(t, cmd.Execute())
			assert.Equal(t, tc.wantOut, stdoutBuf.String())
			assert.Contains(t, stderrBuf.String(), "No secrets found. Use 'skret set' to add a secret.")
		})
	}
}

// --- Env tests ---

func TestEnvCmd_DotenvFormat(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var stdout, stderr bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"env"})

	err := cmd.Execute()
	require.NoError(t, err)
	out := stdout.String()
	// Safe values are emitted bare (no special chars needing quotes).
	assert.Contains(t, out, `DATABASE_URL=postgres://dev:dev@localhost/db`)
	assert.Contains(t, out, `API_KEY=secret123`)
	assert.Empty(t, stderr.String())
}

func TestEnvCmd_ExportFormat(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var stdout, stderr bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"env", "--format=export"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), `export DATABASE_URL='postgres://dev:dev@localhost/db'`)
	assert.Empty(t, stderr.String())
}

// TestEnvCmd_WritesToStdoutNotStderr — regression for bug where cmd.Printf
// routed dotenv output to stderr via cobra's default behaviour, breaking
// shell pipelines like `skret env --format=dotenv > .env`.
func TestEnvCmd_WritesToStdoutNotStderr(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var stdout, stderr bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"env", "--format=dotenv"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), `DATABASE_URL=`,
		"dotenv output MUST go to stdout so pipelines like 'skret env > .env' work")
	assert.NotContains(t, stderr.String(), `DATABASE_URL=`,
		"dotenv output MUST NOT appear on stderr")
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
	cmd2.SetErr(&buf)
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
	cmd2.SetErr(&buf)
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
	cmd2.SetErr(&buf)
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
	// secret123 is safe and emitted bare.
	assert.Contains(t, string(data), "API_KEY=secret123")
}

func TestSyncCmd_SkipUnchanged(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	// Redirect home so SaveSyncState writes inside the test dir.
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	} else {
		t.Setenv("HOME", dir)
	}

	// First sync: state file does not exist, all secrets should be written.
	first := cli.NewRootCmd()
	var firstBuf bytes.Buffer
	first.SetOut(&firstBuf)
	first.SetErr(&firstBuf)
	first.SetArgs([]string{"sync", "--to=dotenv", "--file=.env.synced", "--skip-unchanged"})
	require.NoError(t, first.Execute())
	assert.Contains(t, firstBuf.String(), "Synced")
	assert.NotContains(t, firstBuf.String(), "Skipped")

	// Second sync without changing source: every secret matches the saved
	// state, so the syncer should write zero secrets and report skipped.
	second := cli.NewRootCmd()
	var secondBuf bytes.Buffer
	second.SetOut(&secondBuf)
	second.SetErr(&secondBuf)
	second.SetArgs([]string{"sync", "--to=dotenv", "--file=.env.synced", "--skip-unchanged"})
	require.NoError(t, second.Execute())
	assert.Contains(t, secondBuf.String(), "Skipped")
	assert.Contains(t, secondBuf.String(), "Synced 0 secrets")
}

// --- Additional format tests ---

func TestEnvCmd_JsonYamlFormats(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var stdout, stderr bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"env", "--format=json"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, stdout.String(), `"DATABASE_URL": "postgres://`)
	assert.Empty(t, stderr.String())

	stdout.Reset()
	stderr.Reset()
	cmd2 := cli.NewRootCmd()
	cmd2.SetOut(&stdout)
	cmd2.SetErr(&stderr)
	cmd2.SetArgs([]string{"env", "--format=yaml"})
	require.NoError(t, cmd2.Execute())
	assert.Contains(t, stdout.String(), "DATABASE_URL: postgres://")
	assert.Empty(t, stderr.String())
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
	cmd2.SetErr(&buf)
	cmd2.SetArgs([]string{"get", "FILE_KEY"})
	require.NoError(t, cmd2.Execute())
	assert.Contains(t, buf.String(), "file_value")
}

func TestImportCmd_ConflictSkip(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	envContent := "API_KEY=new_secret\nNEW_KEY=new_value"
	os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0o644)

	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"import", "--from=dotenv", "--file=.env", "--on-conflict=skip"})
	err := cmd.Execute()
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "Imported: 1, Skipped: 1")

	buf.Reset()
	cmd2 := cli.NewRootCmd()
	cmd2.SetOut(&buf)
	cmd2.SetErr(&buf)
	cmd2.SetArgs([]string{"get", "API_KEY"})
	require.NoError(t, cmd2.Execute())
	assert.Equal(t, "secret123\n", buf.String())

	buf.Reset()
	cmd3 := cli.NewRootCmd()
	cmd3.SetOut(&buf)
	cmd3.SetErr(&buf)
	cmd3.SetArgs([]string{"get", "NEW_KEY"})
	require.NoError(t, cmd3.Execute())
	assert.Equal(t, "new_value\n", buf.String())
}

func TestImportCmd_ConflictFail(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	envContent := "API_KEY=new_secret"
	os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0o644)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"import", "--from=dotenv", "--file=.env", "--on-conflict=fail"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "conflict on \"API_KEY\"")
}

// --- Wave 2 T1: bare init must keep good prod defaults (fix C1) ---

func TestInitCmd_BareInit_KeepsGoodProdDefaults(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"init"})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "provider: aws")
	assert.Contains(t, string(data), "/myapp/prod")
	assert.Contains(t, string(data), "us-east-1")
}

func TestInitCmd_PartialFlag_PathOnly_KeepsAWSDefaultProviderAndRegion(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"init", "--path=/custom/prod"})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "provider: aws")
	assert.Contains(t, string(data), "/custom/prod")
	assert.Contains(t, string(data), "us-east-1") // region untouched -- flag not passed
}

// TestInitCmd_C1_BareInit_DevWorksEndToEnd is the audit's exact C1 repro,
// re-run for the fixed behavior: bare `skret init` -> set/get/list on the
// default (dev) env all succeed (used to fail on every command because
// Validate() blocked on the broken prod entry before dev was even looked
// at -- see the config.Validate/Resolve split below in this same task).
func TestInitCmd_C1_BareInit_DevWorksEndToEnd(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	initCmd := cli.NewRootCmd()
	initCmd.SetArgs([]string{"init"})
	require.NoError(t, initCmd.Execute(), "bare `skret init` must succeed")

	setCmd := cli.NewRootCmd()
	setCmd.SetArgs([]string{"set", "FOO", "bar"})
	require.NoError(t, setCmd.Execute(), "bare init: `set` on the default (dev) env must work")

	var getBuf bytes.Buffer
	getCmd := cli.NewRootCmd()
	getCmd.SetOut(&getBuf)
	getCmd.SetArgs([]string{"get", "FOO"})
	require.NoError(t, getCmd.Execute(), "bare init: `get` on the default (dev) env must work")
	assert.Equal(t, "bar\n", getBuf.String())

	var listBuf bytes.Buffer
	listCmd := cli.NewRootCmd()
	listCmd.SetOut(&listBuf)
	listCmd.SetArgs([]string{"list"})
	require.NoError(t, listCmd.Execute(), "bare init: `list` on the default (dev) env must work")
	assert.Contains(t, listBuf.String(), "FOO")
}

// --- Wave 2 T2: --path shell-mangling guard (fix C2) ---

// TestPathMangling_C2_RecoversAndWarns is the audit's exact C2 repro,
// re-run for the fixed behavior. Before the fix: `skret list
// --path=<mangled>` exited 0 with "No secrets found" and NO warning,
// silently querying the wrong prefix. After: still exits 0 (recover-and-warn,
// consistent with the existing key-arg mangling behavior), but a warning
// names the recovered path.
func TestPathMangling_C2_RecoversAndWarns(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	mangledPath := "C:/Users/test/scoop/apps/git/2.54.0/myapp/dev"

	var stderr bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"list", "--provider=local", "--path=" + mangledPath, "--file=./.secrets.dev.yaml"})

	err := cmd.Execute()
	require.NoError(t, err, "C2 fix: a shell-mangled --path must still exit 0, not error")
	assert.Contains(t, stderr.String(), "warning: --path looked shell-mangled")
	assert.Contains(t, stderr.String(), `"/myapp/dev"`)
}

// TestPathMangling_C2_SetThenGetRoundTrip proves the mangled --path and its
// clean equivalent resolve to the SAME location -- the actual risk behind
// C2: a `set` under a mangled --path silently writing under a bogus prefix
// that a later, correctly-typed --path could never find.
func TestPathMangling_C2_SetThenGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	mangledPath := "C:/Users/test/scoop/apps/git/2.54.0/myapp/dev"

	setCmd := cli.NewRootCmd()
	var setErr bytes.Buffer
	setCmd.SetErr(&setErr)
	setCmd.SetArgs([]string{"set", "FOO", "bar", "--provider=local", "--path=" + mangledPath, "--file=./.secrets.dev.yaml"})
	require.NoError(t, setCmd.Execute())
	assert.Contains(t, setErr.String(), "warning: --path looked shell-mangled")

	getCmd := cli.NewRootCmd()
	var getOut bytes.Buffer
	getCmd.SetOut(&getOut)
	getCmd.SetArgs([]string{"get", "FOO", "--provider=local", "--path=/myapp/dev", "--file=./.secrets.dev.yaml"})
	require.NoError(t, getCmd.Execute())
	assert.Equal(t, "bar\n", getOut.String(), "value set under the mangled --path must be readable via the clean equivalent path")
}

// TestInitCmd_M2_GeneratedYAMLOmitsEmptyFields is the fix for audit finding
// M2: a freshly-generated .skret.yaml used to print path/region/profile/
// kms_key_id explicitly as "" for every environment even when unset,
// cluttering the very first file a newcomer is meant to read/edit.
func TestInitCmd_M2_GeneratedYAMLOmitsEmptyFields(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"init"})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
	require.NoError(t, err)
	text := string(data)
	assert.NotContains(t, text, `path: ""`)
	assert.NotContains(t, text, `region: ""`)
	assert.NotContains(t, text, `profile: ""`)
	assert.NotContains(t, text, `kms_key_id: ""`)
	// dev's file field is set, prod's provider/path/region are set -- these
	// must still be present.
	assert.Contains(t, text, "provider: local")
	assert.Contains(t, text, "provider: aws")
	assert.Contains(t, text, "/myapp/prod")
}

// --- Wave 2 T7(c): `completion <bad-shell>` must error, not silently show help (fix M5) ---

func TestCompletionCmd_UnknownShell_Errors(t *testing.T) {
	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"completion", "badshell"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "badshell")
	assert.Contains(t, err.Error(), "bash")
	assert.Contains(t, err.Error(), "zsh")
	assert.Contains(t, err.Error(), "fish")
	assert.Contains(t, err.Error(), "powershell")
}

func TestCompletionCmd_Bare_ShowsHelp(t *testing.T) {
	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"completion"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), "autocompletion script")
}

func TestCompletionCmd_ValidShell_StillGeneratesScript(t *testing.T) {
	// Cobra resolves the completion command's output writer once, when
	// NewRootCmd calls InitDefaultCompletionCmd() at construction time (see
	// root.go), not per Execute() call -- so os.Stdout must be swapped
	// before the root command is built, not merely before Execute.
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"completion", "bash"})

	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()

	execErr := cmd.Execute()
	require.NoError(t, w.Close())
	os.Stdout = orig

	require.NoError(t, execErr)
	assert.Contains(t, <-done, "bash completion")
}
