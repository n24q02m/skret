// internal/cli/set_stdin_fidelity_test.go
package cli_test

import (
	"os"
	"testing"

	"github.com/n24q02m/skret/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setViaStdin pipes value into `skret set <key> --from-stdin` by temporarily
// swapping the process-global os.Stdin (set.go's getValue reads os.Stdin
// directly, not cmd.InOrStdin(), so this is the only way to drive stdin
// end-to-end through the real command tree -- the same technique already
// used by TestSetOptions_GetValue_Stdin and TestSetCmd_FromStdin).
func setViaStdin(t *testing.T, key, value string) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString(value)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"set", key, "--from-stdin"})
	require.NoError(t, cmd.Execute(), "set --from-stdin must accept the piped value")
}

// TestFidelity_SetStdin_MultiLine_ByteExact proves `skret set K --from-stdin`
// preserves a value spanning MULTIPLE lines. bufio.Scanner (the pre-fix
// implementation) calls Scan() exactly once and returns only the first
// line via Text(), silently discarding every line after the first "\n" --
// a PEM key or any multi-line secret piped via stdin would be truncated to
// its first line with no error. This test feeds values whose embedded
// newlines must survive, with no trailing newline (so the trailing-newline
// stripping policy in TestFidelity_SetStdin_TrailingNewlinePolicy below does
// not interact with this assertion).
func TestFidelity_SetStdin_MultiLine_ByteExact(t *testing.T) {
	cases := []struct{ Name, Value string }{
		{"pem", "-----BEGIN-----\nabc\ndef\n-----END-----"},
		{"three_lines", "line1\nline2\nline3"},
		{"crlf_embedded", "crlf\r\nend"},
		{"blank_line_in_middle", "top\n\nbottom"},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			dir := setupTestRepo(t)
			orig, err := os.Getwd()
			require.NoError(t, err)
			require.NoError(t, os.Chdir(dir))
			t.Cleanup(func() { _ = os.Chdir(orig) })

			setViaStdin(t, "K", tc.Value)
			out, err := runCLI(t, "get", "K", "--plain")
			require.NoError(t, err)
			assert.Equal(t, tc.Value, out, "set --from-stdin must preserve embedded newlines byte-exact")
		})
	}
}

// TestFidelity_SetStdin_TrailingNewlinePolicy locks in the deliberate,
// documented policy (see docs/src/content/docs/guide/value-fidelity.md):
// `--from-stdin` strips ALL trailing "\n" bytes from the piped input, the
// same convention `--from-file` already applies to file content (set.go:
// strings.TrimRight(data, "\n")) and the same convention POSIX command
// substitution `$(...)` uses. Only trailing "\n" bytes are stripped -- a
// trailing "\r" (as in a CRLF line ending) is content, not part of the
// stripped cutset, and survives.
func TestFidelity_SetStdin_TrailingNewlinePolicy(t *testing.T) {
	cases := []struct{ Name, Input, Want string }{
		{"single_trailing_nl_stripped", "value\n", "value"},
		{"multiple_trailing_nl_all_stripped", "value\n\n\n", "value"},
		{"trailing_crlf_only_lf_stripped_cr_preserved", "value\r\n", "value\r"},
		{
			"multiline_trailing_nl_stripped_middle_preserved",
			"-----BEGIN-----\nabc\ndef\n-----END-----\n",
			"-----BEGIN-----\nabc\ndef\n-----END-----",
		},
		{"no_trailing_newline_untouched", "value", "value"},
		{"empty_input", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			dir := setupTestRepo(t)
			orig, err := os.Getwd()
			require.NoError(t, err)
			require.NoError(t, os.Chdir(dir))
			t.Cleanup(func() { _ = os.Chdir(orig) })

			setViaStdin(t, "K", tc.Input)
			out, err := runCLI(t, "get", "K", "--plain")
			require.NoError(t, err)
			assert.Equal(t, tc.Want, out)
		})
	}
}

// TestSetCmd_StdinReadError verifies that when os.Stdin is closed,
// getValue's error path (set.go:81-83) is exercised: io.ReadAll fails
// and the command returns an error. This test manipulates the global os.Stdin
// and therefore does NOT use t.Parallel().
func TestSetCmd_StdinReadError(t *testing.T) {
	dir := setupTestRepo(t)
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })

	// Close stdin so io.ReadAll returns an error.
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_ = w.Close()
	_ = r.Close()
	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	// Run set --from-stdin; it should fail with a read error.
	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"set", "K", "--from-stdin"})
	err = cmd.Execute()
	require.Error(t, err, "set --from-stdin with closed stdin must return an error")
}
