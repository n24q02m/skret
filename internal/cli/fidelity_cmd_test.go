package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/cli"
	"github.com/n24q02m/skret/internal/dotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// fidelityCorpus is an 18-value subset of the adversarial classes (see internal/dotenv/fidelity_test.go for the fuller codec corpus).
func fidelityCorpus() []struct{ Name, Value string } {
	c := []struct{ Name, Value string }{
		{"bcrypt", `$2a$14$abcdefghijklmnopqrstuv`},
		{"shell_var", `$HOME`},
		{"brace_ref", `${REF}`},
		{"double_dollar", `$$literal`},
		{"assignment", `key=value`},
		{"newline", "line1\nline2"},
		{"crlf", "crlf\r\nend"},
		{"double_quote", `he said "hi"`},
		{"single_quote", `it's`},
		{"backtick", "`bt`"},
		{"backslash", `a\b\c`},
		{"leading_ws", `  leading`},
		{"trailing_ws", `trailing  `},
		{"tab", "a\tb"},
		{"unicode", `café 日本語 🔐`},
		{"pem", "-----BEGIN-----\nabc\n-----END-----"},
		{"pg_url", `postgres://u:p$w@h:5432/db`},
		{"regex_special", `a.*b[c]$d`},
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
		"version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: ./.secrets.dev.yaml\n",
	), 0o644))
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

// runCLICombined is like runCLI but merges stdout and stderr into a single
// buffer, so assertions can check for output regardless of which stream a
// command writes to (e.g. scan's findings table goes to stdout, but this
// keeps the test robust to that detail).
func runCLICombined(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := cli.NewRootCmd()
	cmd.SetArgs(args)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
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

// TestFidelity_Env_AllFormats_RoundTrip proves `skret env --format=<f>` round-trips
// every corpus value for all 4 dump formats (dotenv, json, yaml, export): the dump
// is parsed BACK by that format's own decoder and compared to the original value.
//
// Two of the four formats can carry a value's embedded newline as a literal
// physical line break in the dump (see parseExportValue doc comment for why
// dotenv does not, despite carrying the same corpus). Both parser helpers below
// are written to be immune to that regardless: parseDotenvValue only needs
// per-line splitting because dotenv.Encode always escapes control bytes (\n,
// \r, \t) rather than emitting them raw, so every entry is exactly one physical
// line; parseExportValue does not split into lines at all -- it walks the raw
// dump byte-by-byte tracking POSIX single-quote state, so an embedded literal
// newline inside the quoted value is just more content, never a delimiter.
func TestFidelity_Env_AllFormats_RoundTrip(t *testing.T) {
	for _, tc := range fidelityCorpus() {
		t.Run(tc.Name, func(t *testing.T) {
			seedLocal(t, tc.Value)

			// dotenv: parse each line back through the codec.
			out, err := runCLI(t, "env", "--format=dotenv")
			require.NoError(t, err)
			gotDot := parseDotenvValue(t, out, "K")
			assert.Equal(t, tc.Value, gotDot, "dotenv format must round-trip")

			// json: whole-document unmarshal.
			out, err = runCLI(t, "env", "--format=json")
			require.NoError(t, err)
			var m map[string]string
			require.NoError(t, json.Unmarshal([]byte(out), &m))
			assert.Equal(t, tc.Value, m["K"], "json format must round-trip")

			// yaml: whole-document unmarshal.
			out, err = runCLI(t, "env", "--format=yaml")
			require.NoError(t, err)
			var my map[string]string
			require.NoError(t, yaml.Unmarshal([]byte(out), &my))
			assert.Equal(t, tc.Value, my["K"], "yaml format must round-trip")

			// export: locate `export K=` then POSIX-single-quote-decode the remainder.
			out, err = runCLI(t, "env", "--format=export")
			require.NoError(t, err)
			assert.Equal(t, tc.Value, parseExportValue(t, out, "K"), "export format must round-trip")
		})
	}
}

// splitLines splits a dump on "\n" and drops a single trailing empty element
// produced by the dump's final newline (fmt.Fprintln/Fprintf always terminate
// the last entry with "\n"). It must NOT be used on the export dump when a
// value may contain a literal embedded newline -- see parseExportValue.
func splitLines(s string) []string {
	lines := strings.Split(s, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

// parseDotenvValue finds `key` in a dotenv-format dump and decodes its value
// via the same dotenv.Decode used by `skret import`. Splitting on physical
// lines is safe here: dotenv.Encode (internal/dotenv/dotenv.go) escapes \n,
// \r and \t to their two-byte C-style forms instead of emitting the raw
// control byte, so a value containing a real newline still renders as a
// single physical output line.
func parseDotenvValue(t *testing.T, dump, key string) string {
	t.Helper()
	for _, line := range splitLines(dump) {
		if k, v, ok := dotenv.Decode(line); ok && k == key {
			return v
		}
	}
	t.Fatalf("key %q not found in dotenv dump: %q", key, dump)
	return ""
}

// parseExportValue finds the `export <key>=` entry in an export-format dump
// and decodes the POSIX single-quoted value that follows it. Unlike dotenv,
// shellSingleQuote (internal/cli/env.go) does NOT escape control bytes -- it
// only rewrites embedded `'` into the close/escape/reopen sequence --
// so a value containing a real newline or CR is written as a literal control
// byte inside the quotes and spans multiple physical lines in the dump. This
// helper therefore never splits the dump into lines; it scans raw bytes and
// tracks single-quote-segment state exactly the way a POSIX shell would, so
// embedded newlines are just ordinary content bytes rather than delimiters.
func parseExportValue(t *testing.T, dump, key string) string {
	t.Helper()
	prefix := "export " + key + "="
	idx := strings.Index(dump, prefix)
	if idx == -1 {
		t.Fatalf("key %q not found in export dump: %q", key, dump)
	}
	return decodeShellSingleQuoted(t, dump[idx+len(prefix):])
}

// TestFidelity_Template_ByteExact proves `skret template` substitutes each
// corpus value into a `${K}` reference byte-exact, straight to stdout (no
// `--output` flag: template.go writes rendered content to cmd.OutOrStdout()
// by default). template.Render uses regexp.ReplaceAllStringFunc with the raw
// value as the replacement, so a value containing `$`, backslashes or a
// literal embedded newline is never re-interpreted or escaped.
func TestFidelity_Template_ByteExact(t *testing.T) {
	for _, tc := range fidelityCorpus() {
		t.Run(tc.Name, func(t *testing.T) {
			dir := seedLocal(t, tc.Value)
			tpl := filepath.Join(dir, "tpl.txt")
			require.NoError(t, os.WriteFile(tpl, []byte("V=${K}"), 0o644))
			out, err := runCLI(t, "template", tpl)
			require.NoError(t, err)
			assert.Equal(t, "V="+tc.Value, out, "template must substitute the value literally")
		})
	}
}

// TestFidelity_SyncImport_Dotenv_RoundTrip proves `skret sync --to=dotenv`
// writes a byte-exact, import-decodable value: the on-disk dump is decoded
// with the same dotenv.Decode used by `skret import` and compared to the
// original value. DotenvSyncer.Sync (internal/syncer/dotenv.go) writes the
// secret's raw, unqualified key straight through dotenv.Encode -- seedLocal's
// .skret.yaml declares no `path:` for the local provider, so the stored key
// is exactly "K" with no prefix to strip, matching parseDotenvValue's lookup.
func TestFidelity_SyncImport_Dotenv_RoundTrip(t *testing.T) {
	for _, tc := range fidelityCorpus() {
		t.Run(tc.Name, func(t *testing.T) {
			dir := seedLocal(t, tc.Value)
			envFile := filepath.Join(dir, "out.env")
			_, err := runCLI(t, "sync", "--to=dotenv", "--file="+envFile)
			require.NoError(t, err)
			// import into a fresh secret name would need a second env; instead assert
			// the on-disk dotenv decodes back to the exact value.
			data, err := os.ReadFile(envFile)
			require.NoError(t, err)
			assert.Equal(t, tc.Value, parseDotenvValue(t, string(data), "K"),
				"sync --to=dotenv must write a byte-exact, import-decodable value")
		})
	}
}

// TestFidelity_Scan_FindsLiteralValue proves `skret scan` detects a managed
// secret value leaked verbatim into leak.txt specifically, including values
// built from regex metacharacters (scanner.scanContent matches via
// bytes.Index, a plain substring search -- never compiled as a pattern).
//
// Asserting only a non-zero exit is not enough: for most of this corpus the
// same value also sits in seedLocal's own .secrets.dev.yaml plaintext store
// (the local provider's on-disk file), which the walk-all fallback below
// sweeps up too, so a non-zero exit would pass even if leak.txt detection
// were broken. Instead this asserts the findings table -- rendered by
// scanner.RenderTable straight to cmd.OutOrStdout() (internal/scanner/result.go)
// -- names leak.txt, proving the newly written file itself was matched.
//
// seedLocal's ".git" is only a placeholder directory (os.MkdirAll), not a
// real repository, so `git ls-files -z` fails inside it (verified: git exits
// 128, "not a git repository") and scanner.TrackedFiles silently falls back
// to walking every file under the working directory (internal/scanner/files.go).
// That fallback already picks up leak.txt with no `git add` needed, so this
// test exercises the real default (non-staged) leak-detection path.
//
// --min-length=0 disables the noise-guard length filter (default 5 bytes):
// several corpus values are shorter than that on purpose (e.g. "it's" is 4
// bytes) and the filter is an intentional, separate feature -- not part of
// the value-fidelity surface under test here.
func TestFidelity_Scan_FindsLiteralValue(t *testing.T) {
	for _, tc := range fidelityCorpus() {
		t.Run(tc.Name, func(t *testing.T) {
			dir := seedLocal(t, tc.Value)
			leak := filepath.Join(dir, "leak.txt")
			require.NoError(t, os.WriteFile(leak, []byte("prefix "+tc.Value+" suffix"), 0o644))
			out, err := runCLICombined(t, "scan", "--min-length=0")
			// scan exits non-zero (code 10, skret.ExitLeakFound) when a managed
			// value is found in a scanned file.
			require.Error(t, err, "scan must detect the leaked value (even regex-special)")
			assert.Contains(t, out, "leak.txt",
				"scan output must reference leak.txt specifically, not just any managed value it happens to find elsewhere (e.g. the local provider's own secrets store)")
		})
	}
}

// decodeShellSingleQuoted decodes a POSIX single-quoted value starting at the
// head of s (s[0] must be the opening quote, as shellSingleQuote always emits
// one, even for the empty string). It reverses shellSingleQuote's
// close/escape/reopen encoding for an embedded quote and treats every other
// byte -- including a literal newline or CR -- as literal value content. It
// stops at the first closing quote that is not immediately followed by the
// `\'` reopen-escape, which is always the true end of the value: content
// bytes between quote delimiters can never themselves contain a raw `'`,
// because shellSingleQuote already replaced every such byte in the source
// value with the 4-byte escape sequence before wrapping in the outer quotes.
func decodeShellSingleQuoted(t *testing.T, s string) string {
	t.Helper()
	var b strings.Builder
	i := 0
	for {
		if i >= len(s) || s[i] != '\'' {
			t.Fatalf("export value: expected opening quote at byte %d in %q", i, s)
		}
		i++ // consume the opening quote
		j := strings.IndexByte(s[i:], '\'')
		if j == -1 {
			t.Fatalf("export value: unterminated quote in %q", s)
		}
		b.WriteString(s[i : i+j])
		i += j + 1 // consume through the closing quote
		if i+1 < len(s) && s[i] == '\\' && s[i+1] == '\'' {
			// close/escape/reopen: an embedded literal quote in the source value.
			b.WriteByte('\'')
			i += 2
			continue
		}
		return b.String()
	}
}
