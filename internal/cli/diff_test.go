package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeLocalDiffConfig writes a .skret.yaml with two local-file environments
// and their backing YAML files. Returns the dir.
func writeLocalDiffConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must := func(name, content string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	must("dev.yaml", "version: \"1\"\nsecrets:\n  DB_URL: dev-url\n  SHARED: same\n  ONLY_DEV: x\n")
	must("prod.yaml", "version: \"1\"\nsecrets:\n  DB_URL: prod-url\n  SHARED: same\n  ONLY_PROD: y\n")
	must(".skret.yaml", `version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: dev.yaml
  prod:
    provider: local
    file: prod.yaml
`)
	return dir
}

func TestDiffCmd_EnvToEnv_Table(t *testing.T) {
	dir := writeLocalDiffConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"diff", "dev", "prod"})
	require.NoError(t, cmd.Execute())

	s := out.String()
	assert.Contains(t, s, "ONLY_DEV")
	assert.Contains(t, s, "ONLY_PROD")
	assert.Contains(t, s, "DB_URL")
	assert.NotContains(t, s, "dev-url")  // value never shown
	assert.NotContains(t, s, "prod-url") // value never shown
}

func TestDiffCmd_ExitCode_OnDrift(t *testing.T) {
	dir := writeLocalDiffConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"diff", "dev", "prod", "--exit-code"})
	require.Error(t, cmd.Execute()) // non-zero because drift exists
}

func TestDiffCmd_JSON(t *testing.T) {
	dir := writeLocalDiffConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"diff", "dev", "prod", "--format", "json"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), `"only_a"`)
	// Values must never appear in JSON output (only_a/changed contain keys).
	assert.NotContains(t, out.String(), "dev-url")
	assert.NotContains(t, out.String(), "prod-url")
}

func TestDiffCmd_EnvToDotenv(t *testing.T) {
	dir := writeLocalDiffConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	envPath := filepath.Join(dir, ".env")
	require.NoError(t, os.WriteFile(envPath, []byte("DB_URL=dotenv-url\nEXTRA=z\n"), 0o600))

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"diff", "dev", "--dotenv", envPath})
	require.NoError(t, cmd.Execute())

	s := out.String()
	assert.Contains(t, s, "DB_URL")        // changed
	assert.Contains(t, s, "ONLY_DEV")      // only in env dev
	assert.Contains(t, s, "EXTRA")         // only in dotenv
	assert.NotContains(t, s, "dev-url")    // value never shown
	assert.NotContains(t, s, "dotenv-url") // value never shown
}

func TestDiffCmd_ValidationErrors(t *testing.T) {
	dir := writeLocalDiffConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	t.Run("dotenv and to conflict", func(t *testing.T) {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"diff", "dev", "--dotenv", "x.env", "--to", "github"})
		require.Error(t, cmd.Execute())
	})

	t.Run("unknown format", func(t *testing.T) {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"diff", "dev", "prod", "--format", "xyz"})
		require.Error(t, cmd.Execute())
	})

	t.Run("github without repo or token", func(t *testing.T) {
		// Unset GITHUB_TOKEN and supply no --github-repo: must fail in
		// buildSecondSide (splitOwnerRepo) before any HTTP call.
		t.Setenv("GITHUB_TOKEN", "")
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"diff", "dev", "--to", "github"})
		require.Error(t, cmd.Execute())
	})

	t.Run("--file with two env positionals", func(t *testing.T) {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"diff", "dev", "prod", "--file", "dev.yaml"})
		require.Error(t, cmd.Execute())
	})
}

func TestDiffCmd_ShowHash(t *testing.T) {
	dir := writeLocalDiffConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"diff", "dev", "prod", "--show-hash"})
	require.NoError(t, cmd.Execute())

	s := out.String()
	assert.Contains(t, s, "DB_URL") // changed key
	assert.Contains(t, s, "→")      // arrow between the two side hashes
	assert.NotContains(t, s, "dev-url")
	assert.NotContains(t, s, "prod-url")
}

func TestDiffCmd_GitHubMissingToken(t *testing.T) {
	dir := writeLocalDiffConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	// Valid --github-repo so splitOwnerRepo succeeds; no GITHUB_TOKEN so the
	// command fails at requireGitHubToken before any HTTP call.
	t.Setenv("GITHUB_TOKEN", "")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"diff", "dev", "--to", "github", "--github-repo", "acme/app"})
	require.Error(t, cmd.Execute())
}

func TestDiffCmd_RawPathLabels(t *testing.T) {
	dir := writeLocalDiffConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	// Positionals starting with "/" are treated as raw provider paths (ad-hoc).
	// Against the local fixture both resolve through the default env, so the
	// snapshots are identical and the command reports no drift.
	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"diff", "/foo", "/bar"})
	require.NoError(t, cmd.Execute())

	s := out.String()
	assert.Contains(t, s, "path:/foo")
	assert.Contains(t, s, "path:/bar")
	assert.Contains(t, s, "no drift")
}
