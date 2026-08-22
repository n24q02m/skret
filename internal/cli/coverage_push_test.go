package cli

import (
	"bytes"
	"os"
	"path/filepath"
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
	cmd.SetErr(&buf)

	o := &initOptions{provider: "local", file: ".secrets.yaml", force: true}
	err := o.run(cmd)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Created")
}

func TestInitOptions_Run_MergesExistingConfigWithoutForce(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	original := []byte("version: \"1\"\nproject: keep-me\ndefault_env: prod\nenvironments:\n  dev:\n    provider: local\n    file: .secrets.dev.yaml\n  prod:\n    provider: aws\n    path: /existing/prod\n    region: us-east-1\nrequired:\n  - API_KEY\nexclude:\n  - DEBUG_*\nsync:\n  targets:\n    - type: github\n      repo: n24q02m/example\n      no_overwrite: true\n")
	require.NoError(t, os.WriteFile(".skret.yaml", original, 0o600))

	cmd := newInitCmd()
	cmd.SetArgs([]string{"--provider=aws", "--path=/updated/prod", "--region=eu-west-1"})
	require.NoError(t, cmd.Execute())

	got, err := os.ReadFile(".skret.yaml")
	require.NoError(t, err)
	text := string(got)
	assert.Contains(t, text, "project: keep-me")
	assert.Contains(t, text, "file: .secrets.dev.yaml")
	assert.Contains(t, text, "path: /updated/prod")
	assert.Contains(t, text, "region: eu-west-1")
	assert.Contains(t, text, "- API_KEY")
	assert.Contains(t, text, "- DEBUG_*")
	assert.Contains(t, text, "no_overwrite: true")
	assert.NotContains(t, text, "path: /existing/prod")
}

func TestInitOptions_Run_RepairsGitignoreForExistingConfig(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	original := []byte("version: \"1\"\ndefault_env: prod\nenvironments:\n  prod:\n    provider: aws\n    path: /existing/prod\n    region: us-east-1\n")
	require.NoError(t, os.WriteFile(".skret.yaml", original, 0o600))
	require.NoError(t, os.WriteFile(".gitignore", []byte(""), 0o600))

	cmd := newInitCmd()
	cmd.SetArgs(nil)
	require.NoError(t, cmd.Execute())

	gotConfig, err := os.ReadFile(".skret.yaml")
	require.NoError(t, err)
	assert.Equal(t, original, gotConfig)
	gotIgnore, err := os.ReadFile(".gitignore")
	require.NoError(t, err)
	assert.Contains(t, string(gotIgnore), ".secrets.*.yaml")
	assert.Contains(t, string(gotIgnore), ".secrets.*.yml")
}
func TestInitOptions_Run_DryRunDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	original := []byte("version: \"1\"\ndefault_env: prod\nenvironments:\n  prod:\n    provider: aws\n    path: /existing/prod\n    region: us-east-1\n")
	require.NoError(t, os.WriteFile(".skret.yaml", original, 0o600))

	cmd := newInitCmd()
	var errOut bytes.Buffer
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"--path=/updated/prod", "--dry-run"})
	require.NoError(t, cmd.Execute())

	got, err := os.ReadFile(".skret.yaml")
	require.NoError(t, err)
	assert.Equal(t, original, got)
	assert.Contains(t, errOut.String(), "dry-run")
	assert.Contains(t, errOut.String(), "/updated/prod")
}

func TestInitOptions_Run_BacksUpBeforeReplacement(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	original := []byte("version: \"1\"\ndefault_env: prod\nenvironments:\n  prod:\n    provider: aws\n    path: /existing/prod\n    region: us-east-1\n")
	require.NoError(t, os.WriteFile(".skret.yaml", original, 0o600))

	cmd := newInitCmd()
	cmd.SetArgs([]string{"--path=/updated/prod"})
	require.NoError(t, cmd.Execute())

	backup, err := os.ReadFile(".skret.yaml.bak")
	require.NoError(t, err)
	assert.Equal(t, original, backup)
	updated, err := os.ReadFile(".skret.yaml")
	require.NoError(t, err)
	assert.Contains(t, string(updated), "path: /updated/prod")
}

func TestInitOptions_Run_SeedsMissingProdEnvironment(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	require.NoError(t, os.WriteFile(".skret.yaml", []byte("version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: .secrets.dev.yaml\n"), 0o600))

	cmd := newInitCmd()
	cmd.SetArgs([]string{"--path=/new/prod"})
	require.NoError(t, cmd.Execute())

	got, err := os.ReadFile(".skret.yaml")
	require.NoError(t, err)
	text := string(got)
	assert.Contains(t, text, "provider: aws")
	assert.Contains(t, text, "path: /new/prod")
}

func TestInitOptions_Run_RejectsBackupSymlink(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	original := []byte("version: \"1\"\ndefault_env: prod\nenvironments:\n  prod:\n    provider: aws\n    path: /existing/prod\n    region: us-east-1\n")
	require.NoError(t, os.WriteFile(".skret.yaml", original, 0o600))
	outside := filepath.Join(dir, "outside.txt")
	require.NoError(t, os.WriteFile(outside, []byte("sentinel"), 0o600))
	if err := os.Symlink(outside, ".skret.yaml.bak"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	cmd := newInitCmd()
	cmd.SetArgs([]string{"--path=/updated/prod"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symlink")

	got, readErr := os.ReadFile(outside)
	require.NoError(t, readErr)
	assert.Equal(t, []byte("sentinel"), got)
	current, readErr := os.ReadFile(".skret.yaml")
	require.NoError(t, readErr)
	assert.Equal(t, original, current)
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
	cmd.SetArgs([]string{"KEY", "1", "--force"}) // skip confirmation prompt
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
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
	cmd.SetErr(&buf)

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
