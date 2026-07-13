package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeEmptyLocalConfig writes a .skret.yaml whose dev env has no secrets, so a
// scan produces no targets and therefore cannot flag any file. Returns the dir.
func writeEmptyLocalConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must := func(name, content string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	must("dev.yaml", "version: \"1\"\nsecrets: {}\n")
	must(".skret.yaml", "version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: dev.yaml\n")
	return dir
}

func TestScanCmd_FindsLeak(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	require.NoError(t, os.WriteFile(filepath.Join(dir, "leaked.env"), []byte("API=tok123\n"), 0o600))

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"scan"})
	err := cmd.Execute()
	require.Error(t, err)

	var se *skret.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, skret.ExitLeakFound, se.Code)

	s := out.String()
	assert.Contains(t, s, "TOKEN")
	assert.Contains(t, s, "leaked.env")
	assert.NotContains(t, s, "tok123")           // value never shown in output
	assert.NotContains(t, err.Error(), "tok123") // value never shown in error
}

func TestScanCmd_Clean(t *testing.T) {
	dir := writeEmptyLocalConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.env"), []byte("API=not-a-secret\n"), 0o600))

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"scan"})
	require.NoError(t, cmd.Execute())

	assert.Contains(t, out.String(), "No secrets found to scan. Use 'skret set' to add a secret.")
}

func TestScanCmd_JSON(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	require.NoError(t, os.WriteFile(filepath.Join(dir, "leaked.env"), []byte("API=tok123\n"), 0o600))

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"scan", "--format", "json"})
	require.Error(t, cmd.Execute())

	s := out.String()
	assert.NotContains(t, s, "tok123") // value never shown in output

	var findings []map[string]any
	require.NoError(t, json.Unmarshal([]byte(s), &findings))
	var keys []string
	for _, f := range findings {
		keys = append(keys, f["key"].(string))
	}
	assert.Contains(t, keys, "TOKEN")
}

func TestScanCmd_Staged(t *testing.T) {
	// Not a git repo, so StagedFiles' `git diff --cached` fails -> wrapped error.
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"scan", "--staged"})
	err := cmd.Execute()
	require.Error(t, err)

	var se *skret.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, skret.ExitGenericError, se.Code)
}

func TestScanCmd_NoConfig_Errors(t *testing.T) {
	dir := t.TempDir() // no .skret.yaml and no --path
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"scan"})
	require.Error(t, cmd.Execute())
}

func TestScanCmd_MinLength(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	require.NoError(t, os.WriteFile(filepath.Join(dir, "leaked.env"), []byte("API=tok123\n"), 0o600))

	// tok123 is 6 chars; --min-length 100 skips every managed value -> no findings.
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"scan", "--min-length", "100"})
	require.NoError(t, cmd.Execute())
}
