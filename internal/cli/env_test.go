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

func TestPrintEnvPairs_JSONMarshalError(t *testing.T) {
	// printEnvPairs with json format and valid data should work fine
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
	// This tests the error path in getEnvPairs when loadProvider fails
	opts := &GlobalOpts{} // no config file in CWD
	_, err := getEnvPairs(opts)
	assert.Error(t, err)
}

func TestNewEnvCmd(t *testing.T) {
	opts := &GlobalOpts{}
	cmd := newEnvCmd(opts)

	assert.Equal(t, "env", cmd.Use)
	assert.True(t, cmd.HasFlags())

	formatFlag := cmd.Flags().Lookup("format")
	require.NotNil(t, formatFlag)
	assert.Equal(t, "dotenv", formatFlag.DefValue)
	assert.Equal(t, "output format (dotenv, json, yaml, export)", formatFlag.Usage)
}

func TestGetEnvPairs_Success(t *testing.T) {
	dir := t.TempDir()
	// Mock a .skret.yaml and a local secrets file
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))
	configData := `
version: "1"
default_env: dev
exclude: ["EXCLUDED_KEY"]
environments:
  dev:
    provider: local
    file: ./secrets.yaml
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(configData), 0o644))

	secretsData := `
version: "1"
secrets:
  Z_KEY: "last"
  A_KEY: "first"
  EXCLUDED_KEY: "gone"
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte(secretsData), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	opts := &GlobalOpts{}
	pairs, err := getEnvPairs(opts)
	require.NoError(t, err)

	require.Len(t, pairs, 2)
	assert.Equal(t, "A_KEY", pairs[0].Name)
	assert.Equal(t, "first", pairs[0].Value)
	assert.Equal(t, "Z_KEY", pairs[1].Name)
	assert.Equal(t, "last", pairs[1].Value)
}

func TestPrintEnvPairs_AllFormats(t *testing.T) {
	pairs := []envPair{
		{Name: "FOO", Value: "bar"},
		{Name: "BAZ", Value: `val "with" quotes`},
	}

	tests := []struct {
		format   string
		contains []string
	}{
		{
			format:   "json",
			contains: []string{`"FOO": "bar"`, `"BAZ": "val \"with\" quotes"`},
		},
		{
			format:   "yaml",
			contains: []string{"FOO: bar", "BAZ: val \"with\" quotes"},
		},
		{
			format:   "export",
			contains: []string{`export FOO="bar"`, `export BAZ="val \"with\" quotes"`},
		},
		{
			format:   "dotenv",
			contains: []string{`FOO="bar"`, `BAZ="val \\\"with\\\" quotes"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			cmd := &cobra.Command{}
			var buf bytes.Buffer
			cmd.SetOut(&buf)

			err := printEnvPairs(cmd, pairs, tt.format)
			require.NoError(t, err)

			out := buf.String()
			for _, c := range tt.contains {
				assert.Contains(t, out, c)
			}
		})
	}
}
