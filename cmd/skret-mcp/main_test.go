package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixture builds a minimal project directory with one local environment.
func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := "version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: .secrets.dev.yaml\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(cfg), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte("version: \"1\"\nsecrets:\n  K: v\n"), 0o600))
	return dir
}

func TestRunVersionFlag(t *testing.T) {
	var out, diags strings.Builder
	code := run([]string{"--version"}, strings.NewReader(""), &out, &diags)
	assert.Equal(t, 0, code)
	assert.Contains(t, out.String(), "skret-mcp")
	assert.Empty(t, diags.String())
}

func TestRunServesOneRequestAndExitsAtEOF(t *testing.T) {
	dir := fixture(t)
	var out, diags strings.Builder
	req := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}` + "\n"
	code := run([]string{"--workdir", dir}, strings.NewReader(req), &out, &diags)
	assert.Equal(t, 0, code)
	assert.Contains(t, out.String(), `"serverInfo"`)
	assert.Empty(t, diags.String())
}

func TestRunBadConfigExitsWithConfigCode(t *testing.T) {
	var out, diags strings.Builder
	code := run([]string{"--workdir", t.TempDir()}, strings.NewReader(""), &out, &diags)
	assert.Equal(t, 2, code, "missing .skret.yaml must exit 2")
	assert.Contains(t, diags.String(), "discover")
}

func TestRunRejectsUnknownFlagsAndArgs(t *testing.T) {
	dir := fixture(t)
	var out, diags strings.Builder

	code := run([]string{"--nope"}, strings.NewReader(""), &out, &diags)
	assert.Equal(t, 2, code)

	diags.Reset()
	code = run([]string{"--workdir", dir, "extra"}, strings.NewReader(""), &out, &diags)
	assert.Equal(t, 2, code)
	assert.Contains(t, diags.String(), "unexpected argument")
}
