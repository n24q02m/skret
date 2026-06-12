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
}
