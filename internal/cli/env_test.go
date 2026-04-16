package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintEnvPairs_JSONMarshalError(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	pairs := []envPair{
		{Name: "KEY", Value: "value"},
	}

	err := printEnvPairs(cmd, pairs, "json")
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `"KEY": "value"`)
}

func TestPrintEnvPairs_YAMLFormat(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	pairs := []envPair{
		{Name: "KEY", Value: "value"},
	}

	err := printEnvPairs(cmd, pairs, "yaml")
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "KEY: value")
}

func TestPrintEnvPairs_ExportFormat(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	pairs := []envPair{
		{Name: "DB_URL", Value: "postgres://localhost"},
	}

	err := printEnvPairs(cmd, pairs, "export")
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `export DB_URL="postgres://localhost"`)
}

func TestPrintEnvPairs_DotenvDefault(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	pairs := []envPair{
		{Name: "KEY", Value: `value with "quotes"`},
	}

	err := printEnvPairs(cmd, pairs, "dotenv")
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `KEY=`)
}

func TestEscapeEnvValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`no quotes`, `no quotes`},
		{`has "double" quotes`, `has \"double\" quotes`},
		{`no special`, `no special`},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, escapeEnvValue(tt.input))
	}
}

func TestGetEnvPairs_ProviderListError(t *testing.T) {
	opts := &GlobalOpts{}
	_, err := getEnvPairs(opts)
	assert.Error(t, err)
}

func TestGetEnvPairs_Success(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	_ = os.MkdirAll(".git", 0o755)
	os.WriteFile(".skret.yaml", []byte(`
version: "1"
default_env: dev
exclude: ["EXCLUDED"]
environments:
  dev:
    provider: local
    file: .secrets.yaml
`), 0o644)

	os.WriteFile(".secrets.yaml", []byte(`
version: "1"
secrets:
  DATABASE_URL: postgres://localhost
  API_KEY: secret-key
  EXCLUDED: should-not-appear
`), 0o600)

	opts := &GlobalOpts{}
	pairs, err := getEnvPairs(opts)
	require.NoError(t, err)
	require.Len(t, pairs, 2)

	// Sorted by name
	assert.Equal(t, "API_KEY", pairs[0].Name)
	assert.Equal(t, "secret-key", pairs[0].Value)
	assert.Equal(t, "DATABASE_URL", pairs[1].Name)
	assert.Equal(t, "postgres://localhost", pairs[1].Value)
}

func TestNewEnvCmd(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	_ = os.MkdirAll(".git", 0o755)
	os.WriteFile(".skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: .secrets.yaml
`), 0o644)
	os.WriteFile(".secrets.yaml", []byte(`
version: "1"
secrets:
  FOO: bar
`), 0o600)

	opts := &GlobalOpts{}
	cmd := newEnvCmd(opts)
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"env", "--format=json"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `"FOO": "bar"`)
}
