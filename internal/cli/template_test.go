package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeLocalTemplateConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must := func(name, content string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	must("dev.yaml", "version: \"1\"\nsecrets:\n  DB_URL: postgres://secret-host\n  TOKEN: tok123\n")
	must(".skret.yaml", "version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: dev.yaml\n")
	return dir
}

func TestTemplateCmd_RendersToStdout(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.conf.tpl"),
		[]byte("url=${DB_URL}\nbearer=${TOKEN}\nliteral=$HOME\n"), 0o600))

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"template", "app.conf.tpl"})
	require.NoError(t, cmd.Execute())

	s := out.String()
	assert.Contains(t, s, "url=postgres://secret-host")
	assert.Contains(t, s, "bearer=tok123")
	assert.Contains(t, s, "literal=$HOME")
}

func TestTemplateCmd_OutputFile(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	require.NoError(t, os.WriteFile(filepath.Join(dir, "in.tpl"), []byte("X=${TOKEN}\n"), 0o600))
	outPath := filepath.Join(dir, "out.conf")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"template", "in.tpl", "--output", outPath})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "X=tok123\n", string(data))
}

func TestTemplateCmd_MissingKey_Errors(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.tpl"), []byte("${DB_URL} ${NOPE}\n"), 0o600))
	outPath := filepath.Join(dir, "should-not-exist.conf")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"template", "bad.tpl", "--output", outPath})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOPE")
	assert.NotContains(t, err.Error(), "postgres")
	assert.NoFileExists(t, outPath)
}

func TestTemplateCmd_MissingFile_Errors(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"template", "nope.tpl"})
	require.Error(t, cmd.Execute())
}

func TestTemplateCmd_OutputWriteError(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	require.NoError(t, os.WriteFile(filepath.Join(dir, "in.tpl"), []byte("X=${TOKEN}\n"), 0o600))
	// --output points at the existing directory, so the file write must fail.
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"template", "in.tpl", "--output", dir})
	require.Error(t, cmd.Execute())
}

func TestTemplateCmd_NoConfig_Errors(t *testing.T) {
	dir := t.TempDir() // no .skret.yaml here
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	require.NoError(t, os.WriteFile(filepath.Join(dir, "x.tpl"), []byte("${A}\n"), 0o600))
	// Template file reads fine, then loadProvider fails: no config and no --path.
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"template", "x.tpl"})
	require.Error(t, cmd.Execute())
}

func TestTemplateCmd_EscapeAndBareDollar(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	require.NoError(t, os.WriteFile(filepath.Join(dir, "e.tpl"),
		[]byte("real=${TOKEN}\nbare=$PATH\nliteral=$${TOKEN}\n"), 0o600))

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"template", "e.tpl"})
	require.NoError(t, cmd.Execute())

	s := out.String()
	assert.Contains(t, s, "real=tok123")      // ${TOKEN} substituted
	assert.Contains(t, s, "bare=$PATH")       // bare $ untouched
	assert.Contains(t, s, "literal=${TOKEN}") // $$ escape -> literal ${TOKEN}, not substituted
}
