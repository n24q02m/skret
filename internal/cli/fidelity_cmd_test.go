package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fidelityCorpus is an 18-value subset of the adversarial classes (see internal/dotenv/fidelity_test.go for the fuller codec corpus).
func fidelityCorpus() []struct{ Name, Value string } {
	c := []struct{ Name, Value string }{
		{"bcrypt", `$2a$14$abcdefghijklmnopqrstuv`}, {"shell_var", `$HOME`},
		{"brace_ref", `${REF}`}, {"double_dollar", `$$literal`}, {"assignment", `key=value`},
		{"newline", "line1\nline2"}, {"crlf", "crlf\r\nend"}, {"double_quote", `he said "hi"`},
		{"single_quote", `it's`}, {"backtick", "`bt`"}, {"backslash", `a\b\c`},
		{"leading_ws", `  leading`}, {"trailing_ws", `trailing  `}, {"tab", "a\tb"},
		{"unicode", `café 日本語 🔐`}, {"pem", "-----BEGIN-----\nabc\n-----END-----"},
		{"pg_url", `postgres://u:p$w@h:5432/db`}, {"regex_special", `a.*b[c]$d`},
	}
	return c
}

// seedLocal creates a temp repo with the local provider and seeds K=value via
// `skret set` (exercises the write path). Returns the repo dir. cwd is changed
// to the repo for the duration of the test (restored via t.Cleanup).
func seedLocal(t *testing.T, value string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(
		"version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: ./.secrets.dev.yaml\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte("version: \"1\"\nsecrets: {}\n"), 0o600))
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"set", "--", "K", value})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	require.NoError(t, cmd.Execute(), "set must accept value verbatim")
	return dir
}

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := cli.NewRootCmd()
	cmd.SetArgs(args)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	return out.String(), err
}

func TestFidelity_SetGet_ByteExact(t *testing.T) {
	for _, tc := range fidelityCorpus() {
		t.Run(tc.Name, func(t *testing.T) {
			seedLocal(t, tc.Value)
			out, err := runCLI(t, "get", "K", "--plain")
			require.NoError(t, err)
			assert.Equal(t, tc.Value, out, "get --plain must return the exact stored value")
		})
	}
}
