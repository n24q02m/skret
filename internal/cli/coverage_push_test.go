package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- loadProvider error paths ---

func TestLoadProvider_NoConfig(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	_, _, err := loadProvider(&GlobalOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config")
}

func TestLoadProvider_InvalidProvider(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: nonexistent
    file: ./secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets: {}"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	_, _, err := loadProvider(&GlobalOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "provider")
}

func TestLoadProvider_EnvOverride(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./secrets.yaml
  staging:
    provider: local
    file: ./secrets-staging.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  KEY: dev_val"), 0o600))
	require.NoError(t, os.WriteFile(dir+"/secrets-staging.yaml", []byte("version: \"1\"\nsecrets:\n  KEY: staging_val"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cfg, p, err := loadProvider(&GlobalOpts{Env: "staging"})
	require.NoError(t, err)
	defer p.Close()
	assert.Equal(t, "local", cfg.Provider)
}

// --- init command error paths ---

func TestInitOptions_Run_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte("existing"), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	o := &initOptions{force: false}
	err := o.run(cmd)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestInitOptions_Run_ForceOverwrite(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte("old content"), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	o := &initOptions{provider: "local", file: ".secrets.yaml", force: true}
	err := o.run(cmd)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Created")
}

// --- rollback command paths ---

func TestRollback_NonExperimental(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  KEY: val"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	t.Setenv("SKRET_EXPERIMENTAL", "0")
	cmd := newRollbackCmd(&GlobalOpts{})
	cmd.SetArgs([]string{"KEY", "1"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "experimental")
}

func TestRollback_InvalidVersion(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  KEY: val"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	t.Setenv("SKRET_EXPERIMENTAL", "1")
	cmd := newRollbackCmd(&GlobalOpts{})
	cmd.SetArgs([]string{"KEY", "not-a-number"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid version")
}

func TestRollback_CapabilityNotSupported(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  KEY: val"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	t.Setenv("SKRET_EXPERIMENTAL", "1")
	cmd := newRollbackCmd(&GlobalOpts{})
	cmd.SetArgs([]string{"KEY", "1"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rollback")
}

// --- history command paths ---

func TestHistory_NonExperimental(t *testing.T) {
	t.Setenv("SKRET_EXPERIMENTAL", "0")
	cmd := newHistoryCmd(&GlobalOpts{})
	cmd.SetArgs([]string{"KEY"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "experimental")
}

func TestHistory_CapabilityNotSupported(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  KEY: val"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	t.Setenv("SKRET_EXPERIMENTAL", "1")
	cmd := newHistoryCmd(&GlobalOpts{})
	cmd.SetArgs([]string{"KEY"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "history")
}

// --- set command via stdin ---

func TestSetOptions_GetValue_Stdin(t *testing.T) {
	r, w, _ := os.Pipe()
	_, err := w.WriteString("stdin_value\n")
	require.NoError(t, err)
	w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	o := &setOptions{fromStdin: true}
	val, err := o.getValue([]string{"KEY"})
	require.NoError(t, err)
	assert.Equal(t, "stdin_value", val)
}

// --- execCommand error paths ---

func TestExecCommand_NotFound(t *testing.T) {
	err := execCommand([]string{"this_command_does_not_exist_12345"}, os.Environ())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "command not found")
}

// --- buildSyncers error paths ---

func TestBuildSyncers_GithubNoToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	_, err := buildSyncers("github", "", "owner/repo")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GITHUB_TOKEN")
}

func TestBuildSyncers_GithubInvalidRepo(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	_, err := buildSyncers("github", "", "invalid-no-slash")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid repo format")
}

func TestBuildSyncers_GithubEmptyRepo(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	_, err := buildSyncers("github", "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one repository")
}

func TestBuildSyncers_UnknownTarget(t *testing.T) {
	_, err := buildSyncers("unknown-target", "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown target")
}

func TestBuildSyncers_DotenvWithCustomFile(t *testing.T) {
	syncers, err := buildSyncers("dotenv", "custom.env", "")
	require.NoError(t, err)
	assert.Len(t, syncers, 1)
	assert.Equal(t, "dotenv", syncers[0].Name())
}

// --- printEnvPairs unknown format ---

func TestPrintEnvPairs_UnknownFormat(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	pairs := []envPair{
		{Name: "KEY", Value: "value"},
	}

	// Unknown format falls through to default (dotenv)
	err := printEnvPairs(cmd, pairs, "unknown-format")
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "KEY=")
}

// --- appendGitignore idempotent ---

func TestAppendGitignore_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/.gitignore"

	// First call adds entries
	require.NoError(t, appendGitignore(path))
	data1, _ := os.ReadFile(path)

	// Second call should not duplicate
	require.NoError(t, appendGitignore(path))
	data2, _ := os.ReadFile(path)

	assert.Equal(t, string(data1), string(data2))
}
