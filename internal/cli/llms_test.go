package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/version"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runLLMs executes `skret llms [args...]` against a fresh root command and
// returns stdout. cobra materializes its built-in help command during
// Execute, so the tree walked after this call matches the one the manifest
// was built from.
func runLLMs(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	root := NewRootCmd()
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(append([]string{"llms"}, args...))
	err := root.Execute()
	return out.String(), err
}

// runLLMsJSON executes `skret llms --format json` and decodes the manifest.
func runLLMsJSON(t *testing.T) llmsManifest {
	t.Helper()
	out, err := runLLMs(t, "--format", "json")
	require.NoError(t, err)
	var m llmsManifest
	require.NoError(t, json.Unmarshal([]byte(out), &m), "stdout must be valid llms JSON:\n%s", out)
	return m
}

// visibleCommandPaths walks the tree the way llms.go does and returns every
// non-hidden command path.
func visibleCommandPaths(root *cobra.Command) []string {
	var out []string
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if !c.Hidden {
			out = append(out, c.CommandPath())
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	sort.Strings(out)
	return out
}

func TestLLMsJSONShape(t *testing.T) {
	m := runLLMsJSON(t)

	assert.Equal(t, version.Version, m.Version, "version must match the build version")
	assert.NotEmpty(t, m.Commands)
	assert.Equal(t, defaultRegistry().Providers(), m.Providers, "providers must come from the live registry")
	assert.NotEmpty(t, m.EnvVars)
	assert.NotEmpty(t, m.ConfigKeys)

	// exit_codes carries exactly the documented class codes, keyed by the
	// string form of the pkg/skret constants.
	want := map[string]string{}
	for _, row := range llmsExitCodeTable {
		want[strconv.Itoa(row.code)] = row.Constant + " — " + row.Meaning
	}
	assert.Equal(t, want, m.ExitCodes)

	// Rows are name-sorted so output is byte-stable.
	assert.True(t, sort.SliceIsSorted(m.EnvVars, func(i, j int) bool { return m.EnvVars[i].Name < m.EnvVars[j].Name }))
	assert.True(t, sort.SliceIsSorted(m.ConfigKeys, func(i, j int) bool { return m.ConfigKeys[i].Name < m.ConfigKeys[j].Name }))
	assert.True(t, sort.SliceIsSorted(m.Commands, func(i, j int) bool { return m.Commands[i].Command < m.Commands[j].Command }))
}

func TestLLMsManifestCoversCommandTree(t *testing.T) {
	var out bytes.Buffer
	root := NewRootCmd()
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"llms", "--format", "json"})
	require.NoError(t, root.Execute())

	var m llmsManifest
	require.NoError(t, json.Unmarshal(out.Bytes(), &m))
	got := make(map[string]llmsCommand, len(m.Commands))
	for _, c := range m.Commands {
		got[c.Command] = c
	}
	for _, path := range visibleCommandPaths(root) {
		row, ok := got[path]
		assert.True(t, ok, "manifest must list command %q", path)
		if ok {
			assert.NotEmpty(t, row.Short, "command %q must carry its Short description", path)
		}
	}
}

// TestLLMsCommandFlagsAreLocalFlags spot-checks that per-command flag lists
// carry the command's own flags, not another command's.
func TestLLMsCommandFlagsAreLocalFlags(t *testing.T) {
	m := runLLMsJSON(t)
	byName := make(map[string]llmsCommand, len(m.Commands))
	for _, c := range m.Commands {
		byName[c.Command] = c
	}

	audit, ok := byName["skret audit"]
	require.True(t, ok)
	for _, want := range []string{"--since", "--key", "--limit", "--format"} {
		assert.Contains(t, audit.Flags, want, "skret audit must list %s", want)
	}
	assert.NotContains(t, audit.Flags, "--timeout", "skret audit must not claim doctor's flag")

	doctor, ok := byName["skret doctor"]
	require.True(t, ok)
	assert.Contains(t, doctor.Flags, "--timeout")

	root, ok := byName["skret"]
	require.True(t, ok)
	assert.Contains(t, root.Flags, "--env", "root row must list the global persistent flags")
	assert.Contains(t, root.Flags, "--log-level")
}

// TestLLMsEnvVarsMatchSource scans every non-test .go file under internal/,
// pkg/, and cmd/ for SKRET_ variable reads and fails when a variable the
// program reads is missing from the manifest table.
func TestLLMsEnvVarsMatchSource(t *testing.T) {
	m := runLLMsJSON(t)
	documented := make(map[string]bool, len(m.EnvVars))
	for _, e := range m.EnvVars {
		documented[e.Name] = true
	}

	repoRoot := filepath.Join("..", "..")
	var candidates []string
	for _, dir := range []string{"internal", "pkg", "cmd"} {
		root := filepath.Join(repoRoot, dir)
		require.DirExists(t, root)
		candidates = append(candidates, collectGoFiles(t, root)...)
	}

	readRe := regexp.MustCompile(`SKRET_[A-Z_]+`)
	seen := map[string]bool{}
	for _, file := range candidates {
		if strings.HasSuffix(file, "_test.go") || strings.HasSuffix(file, "llms.go") {
			continue // the manifest table itself is the expected set, not a usage
		}
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		for _, name := range readRe.FindAllString(string(data), -1) {
			seen[name] = true
		}
	}
	require.NotEmpty(t, seen, "source scan must find at least one SKRET_ variable")
	for name := range seen {
		assert.True(t, documented[name], "SKRET_ variable %s is read in source but missing from the llms manifest", name)
	}
}

// TestLLMsConfigKeysMatchSchema parses the yaml tags out of
// internal/config/schema.go and fails when a declared config key is missing
// from the manifest.
func TestLLMsConfigKeysMatchSchema(t *testing.T) {
	m := runLLMsJSON(t)
	documented := make(map[string]bool, len(m.ConfigKeys))
	for _, k := range m.ConfigKeys {
		documented[k.Name] = true
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "config", "schema.go"))
	require.NoError(t, err)
	tagRe := regexp.MustCompile(`yaml:"([a-z_]+)`)
	seen := map[string]bool{}
	for _, match := range tagRe.FindAllStringSubmatch(string(data), -1) {
		seen[match[1]] = true
	}
	require.NotEmpty(t, seen, "schema scan must find at least one yaml key")
	for name := range seen {
		assert.True(t, documented[name], "config key %q is declared in schema.go but missing from the llms manifest", name)
	}
}

// TestLLMsNeverTouchesSecretData runs llms in a directory holding a config
// and secrets file with a canary key/value; neither may appear in any output
// format.
func TestLLMsNeverTouchesSecretData(t *testing.T) {
	dir := t.TempDir()
	configYAML := "version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: .secrets.dev.yaml\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(configYAML), 0o600))
	secretsYAML := "LLMS_CANARY_KEY: llms-canary-value-9f2c1e\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte(secretsYAML), 0o600))

	t.Chdir(dir)
	for _, args := range [][]string{nil, {"--format", "json"}} {
		out, err := runLLMs(t, args...)
		require.NoError(t, err)
		assert.NotContains(t, out, "LLMS_CANARY_KEY", "llms must never emit secret key names")
		assert.NotContains(t, out, "llms-canary-value-9f2c1e", "llms must never emit secret values")
	}
}

// TestLLMsDeterministicBytes pins the byte-exact contract: identical
// invocations produce identical stdout.
func TestLLMsDeterministicBytes(t *testing.T) {
	for _, args := range [][]string{nil, {"--format", "json"}} {
		first, err := runLLMs(t, args...)
		require.NoError(t, err)
		second, err := runLLMs(t, args...)
		require.NoError(t, err)
		assert.Equal(t, first, second, "llms output must be byte-exact across runs (args=%v)", args)
		assert.True(t, strings.HasSuffix(first, "\n"), "output must end with a trailing newline")
	}
}

func TestLLMsRejectsUnknownFormat(t *testing.T) {
	_, err := runLLMs(t, "--format", "yaml")
	require.Error(t, err)
	assert.Equal(t, skret.ExitValidationError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), `llms: unknown --format "yaml"`)
}

func TestLLMsRejectsPositionalArgs(t *testing.T) {
	_, err := runLLMs(t, "extra")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown command")
}

// collectGoFiles walks root and returns every .go file path.
func collectGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	require.NoError(t, filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	}))
	return out
}
