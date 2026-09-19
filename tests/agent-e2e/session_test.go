package agente2e_test

// The scripted agent session: every step an unattended agent performs on a
// fresh project — init a local provider, write and read secrets byte-exactly,
// generate and rotate values, run a child process with injected env, health-
// check, and leak-scan — with the documented contract asserted at each step.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// seedKey/seedValue land in the provider file before init so the session also
// covers reading pre-existing state, the way an agent meets an existing repo.
const (
	seedKey   = "SEED_KEY"
	seedValue = "seed-value"
)

func writeProviderFile(t *testing.T, dir string) {
	t.Helper()
	body := fmt.Sprintf("version: \"1\"\nsecrets:\n  %s: \"%s\"\n", seedKey, seedValue)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte(body), 0o600))
}

func gitInit(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "core.autocrlf", "false"},
	} {
		cmd := exec.CommandContext(context.Background(), "git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
}

// TestAgentE2E_ContractSession is the harness. Run it against any skret build:
//
//	SKRET_AGENT_E2E_BINARY=./skret go test ./tests/agent-e2e/ -run TestAgentE2E_ContractSession -v
//
// It must stay green on every platform CI targets; platform-specific promises
// are conditionalized below with the reason in a comment, never skipped whole.
func TestAgentE2E_ContractSession(t *testing.T) {
	if testing.Short() {
		t.Skip("agent e2e drives the real binary; skipped in -short mode")
	}
	binary := buildSkret(t)

	// Fresh workspace, own git repo: skret's config discovery walks to the git
	// root and scan works on tracked files, so the session needs a real repo.
	dir := t.TempDir()
	gitInit(t, dir)
	writeProviderFile(t, dir)
	s := newSession(t, binary, dir)

	// --version identifies the binary before anything else is trusted.
	inv := s.run("version", "--version")
	s.expectExit(inv, 0)
	s.expectStdoutContains(inv, "skret")

	// Missing config, plain: distinct documented exit code, nothing on stdout.
	inv = s.run("get-without-config", "get", "ANY")
	s.expectExit(inv, 2)
	s.expectStdoutEmpty(inv)
	s.expectStderrContains(inv, ".skret.yaml")

	// Missing config, --format json: the error envelope, code agreeing with exit.
	inv = s.run("get-without-config-json", "get", "ANY", "--format", "json")
	s.expectExit(inv, 2)
	s.expectEnvelope(inv, 2)

	// init: status on stderr, stdout stays empty.
	inv = s.run("init", "init", "--provider=local", "--file=./.secrets.dev.yaml")
	s.expectExit(inv, 0)
	s.expectStdoutEmpty(inv)
	s.expectStderrContains(inv, "Created")

	// get (default form): value plus exactly one trailing newline on stdout,
	// nothing on stderr.
	inv = s.run("get-seed", "get", seedKey)
	s.expectExit(inv, 0)
	s.expectStdoutBytes(inv, []byte(seedValue+"\n"))
	s.expectStderrEmpty(inv)

	// get --plain: byte-exact stored bytes, newline added by nobody.
	inv = s.run("get-seed-plain", "get", seedKey, "--plain")
	s.expectExit(inv, 0)
	s.expectStdoutBytes(inv, []byte(seedValue))

	// get missing, table: exit 5 (ExitNotFoundError), prose on stderr only.
	inv = s.run("get-missing", "get", "MISSING_KEY")
	s.expectExit(inv, 5)
	s.expectStdoutEmpty(inv)
	s.expectStderrContains(inv, "MISSING_KEY")

	// get missing, --format json: the envelope on stderr, exit 5, code 5.
	inv = s.run("get-missing-json", "get", "MISSING_KEY", "--format", "json")
	s.expectExit(inv, 5)
	s.expectEnvelope(inv, 5)

	// set (table): status line on stderr, stdout empty — data belongs on stdout
	// and there is no data here.
	inv = s.run("set-alpha", "set", "ALPHA_KEY", "alpha-value")
	s.expectExit(inv, 0)
	s.expectStdoutEmpty(inv)
	s.expectStderrContains(inv, "Set ALPHA_KEY")

	// set --from-stdin --format json (new key): payload on stdout with the
	// documented fields; created must be true for a first write. The value
	// never appears in the payload.
	inv = s.withStdin([]byte("line1\nline2\n")).run("set-multiline-json", "set", "MULTI_KEY", "--from-stdin", "--format", "json")
	s.expectExit(inv, 0)
	obj := s.expectJSONObject(inv)
	if obj != nil {
		s.expectJSONFieldString(obj, inv.name, "key", "MULTI_KEY")
		s.expectJSONFieldBool(obj, inv.name, "created", true)
		if _, hasValue := obj["value"]; hasValue {
			s.violate(inv, "set payload must never carry the secret value", fmt.Sprint(obj))
		}
	}

	// The stored value survives byte-exactly: trailing newline stripped on the
	// way in (documented stdin rule), embedded newline intact, and the default
	// get form adds exactly one newline back on the way out.
	inv = s.run("get-multiline-plain", "get", "MULTI_KEY", "--plain")
	s.expectExit(inv, 0)
	s.expectStdoutBytes(inv, []byte("line1\nline2"))
	inv = s.run("get-multiline", "get", "MULTI_KEY")
	s.expectExit(inv, 0)
	s.expectStdoutBytes(inv, []byte("line1\nline2\n"))

	// Overwrite via --format json: created must flip to false.
	inv = s.run("set-alpha-overwrite-json", "set", "ALPHA_KEY", "alpha-v2", "--format", "json")
	s.expectExit(inv, 0)
	obj = s.expectJSONObject(inv)
	if obj != nil {
		s.expectJSONFieldString(obj, inv.name, "key", "ALPHA_KEY")
		s.expectJSONFieldBool(obj, inv.name, "created", false)
	}

	// Byte-exact fidelity: trailing space, multibyte UTF-8, and an embedded
	// NUL (via stdin — argv cannot carry one) must round-trip unmodified.
	inv = s.run("set-trailing-space", "set", "SPACE_KEY", "v ")
	s.expectExit(inv, 0)
	inv = s.run("get-trailing-space", "get", "SPACE_KEY", "--plain")
	s.expectExit(inv, 0)
	s.expectStdoutBytes(inv, []byte("v "))

	const multibyte = "héllo-日本語-🔑"
	inv = s.run("set-multibyte", "set", "UTF_KEY", multibyte)
	s.expectExit(inv, 0)
	inv = s.run("get-multibyte", "get", "UTF_KEY", "--plain")
	s.expectExit(inv, 0)
	s.expectStdoutBytes(inv, []byte(multibyte))

	inv = s.withStdin([]byte("a\x00b")).run("set-nul", "set", "NUL_KEY", "--from-stdin")
	s.expectExit(inv, 0)
	inv = s.run("get-nul", "get", "NUL_KEY", "--plain")
	s.expectExit(inv, 0)
	s.expectStdoutBytes(inv, []byte("a\x00b"))

	// list (table): key names on stdout, empty stderr.
	inv = s.run("list", "list")
	s.expectExit(inv, 0)
	s.expectStderrEmpty(inv)
	for _, k := range []string{seedKey, "ALPHA_KEY", "MULTI_KEY", "SPACE_KEY", "UTF_KEY", "NUL_KEY"} {
		s.expectStdoutContains(inv, k)
	}

	// list --format json: array of objects, each carrying its key name.
	inv = s.run("list-json", "list", "--format", "json")
	s.expectExit(inv, 0)
	arr := s.expectJSONArray(inv)
	if arr != nil {
		seen := map[string]bool{}
		for _, e := range arr {
			if m, ok := e.(map[string]any); ok {
				if k, ok := m["key"].(string); ok {
					seen[k] = true
				}
			}
		}
		for _, k := range []string{seedKey, "ALPHA_KEY", "MULTI_KEY"} {
			if !seen[k] {
				s.violate(inv, fmt.Sprintf("list json entry for %q", k), fmt.Sprint(seen))
			}
		}
	}

	// env (dotenv): KEY=value lines on stdout, empty stderr.
	inv = s.run("env", "env")
	s.expectExit(inv, 0)
	s.expectStderrEmpty(inv)
	s.expectStdoutContains(inv, "ALPHA_KEY=alpha-v2")

	// env --format json: object map, value preserved byte-exactly.
	inv = s.run("env-json", "env", "--format", "json")
	s.expectExit(inv, 0)
	obj = s.expectJSONObject(inv)
	if obj != nil {
		s.expectJSONFieldString(obj, inv.name, "ALPHA_KEY", "alpha-v2")
		s.expectJSONFieldString(obj, inv.name, "MULTI_KEY", "line1\nline2")
	}

	// run --: the child sees the resolved secret as a real environment
	// variable. The child is this test binary re-executed in child mode (see
	// TestMain) so the assertion has no shell dependency on any platform.
	child, err := os.Executable()
	require.NoError(t, err)
	s.extraEnv = []string{"AGENT_E2E_CHILD_MODE=print-env", "AGENT_E2E_CHILD_ENV=ALPHA_KEY"}
	inv = s.run("run-inject", "run", "--", child)
	s.expectExit(inv, 0)
	s.expectStdoutBytes(inv, []byte("alpha-v2\n"))
	s.expectStderrEmpty(inv)

	// run -- forwards the child's exit code (spec: exit 42 propagates).
	// Verified on unix, where skret replaces itself via syscall.Exec and the
	// child's code is skret's code. Windows runs a child process and maps a
	// non-zero child exit to ExitExecError (125) instead — a documented
	// platform difference, asserted as such rather than skipped silently.
	s.extraEnv = []string{"AGENT_E2E_CHILD_MODE=exit", "AGENT_E2E_CHILD_EXIT=42"}
	inv = s.run("run-exit-code", "run", "--", child)
	if runtime.GOOS == "windows" {
		s.expectExit(inv, 125)
	} else {
		s.expectExit(inv, 42)
	}
	s.extraEnv = nil

	// run -- with a nonexistent command: exit 125 (ExitExecError), nothing on
	// stdout.
	inv = s.run("run-missing-cmd", "run", "--", "definitely-not-a-real-command-xyz")
	s.expectExit(inv, 125)
	s.expectStdoutEmpty(inv)
	s.expectStderrContains(inv, "not found")

	// generate (table): exactly length chars + one newline, alnum charset,
	// status-free stderr, and different values across runs (real randomness).
	inv = s.run("generate-password", "generate", "--type", "password", "--length", "32")
	s.expectExit(inv, 0)
	require.Len(t, inv.stdout, 33, "generate must emit exactly length chars plus newline")
	require.Equal(t, byte('\n'), inv.stdout[32])
	for _, c := range inv.stdout[:32] {
		require.True(t, c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z',
			"alnum charset violated: %q in %q", c, inv.stdout)
	}
	s.expectStderrEmpty(inv)
	first := string(inv.stdout[:32])
	inv = s.run("generate-password-again", "generate", "--type", "password", "--length", "32")
	s.expectExit(inv, 0)
	if string(inv.stdout[:32]) == first {
		s.violate(inv, "two generate runs differ (real randomness)", "identical values")
	}

	// generate --format json: documented payload, value matches hex charset.
	inv = s.run("generate-hex-json", "generate", "--type", "hex", "--length", "16", "--format", "json")
	s.expectExit(inv, 0)
	obj = s.expectJSONObject(inv)
	if obj != nil {
		s.expectJSONFieldString(obj, inv.name, "type", "hex")
		if v, ok := obj["value"].(string); !ok || len(v) != 16 {
			s.violate(inv, `generate json "value" of length 16`, fmt.Sprint(obj["value"]))
		} else if _, err := strconv.ParseUint(v, 16, 64); err != nil {
			s.violate(inv, "hex value parses as hex", v)
		}
	}

	// generate with an unknown type: exit 8 (ExitValidationError) + envelope.
	inv = s.run("generate-bad-type", "generate", "--type", "bogus")
	s.expectExit(inv, 8)
	s.expectStdoutEmpty(inv)
	inv = s.run("generate-bad-type-json", "generate", "--type", "bogus", "--format", "json")
	s.expectExit(inv, 8)
	s.expectEnvelope(inv, 8)

	// rotate: value replaced by a fresh generated value, never printed by
	// default (stdout empty, status on stderr).
	inv = s.run("rotate-alpha", "rotate", "ALPHA_KEY")
	s.expectExit(inv, 0)
	s.expectStdoutEmpty(inv)
	s.expectStderrContains(inv, "Rotated ALPHA_KEY")
	inv = s.run("get-after-rotate", "get", "ALPHA_KEY", "--plain")
	s.expectExit(inv, 0)
	require.Len(t, inv.stdout, 32, "rotate default generates a 32-char password")
	if string(inv.stdout) == "alpha-v2" {
		s.violate(s.invocations[len(s.invocations)-1], "rotated value differs from the old one", "unchanged")
	}

	// rotate --show: the new value on stdout, one line — the value's bytes
	// plus exactly one trailing newline; the bytes before it must match a
	// later read byte-for-byte.
	inv = s.run("rotate-show", "rotate", "ALPHA_KEY", "--show")
	s.expectExit(inv, 0)
	shown := inv.stdout
	require.True(t, bytes.HasSuffix(shown, []byte("\n")), "rotate --show must print the value as one line, got %q", shown)
	inv = s.run("get-rotate-show", "get", "ALPHA_KEY", "--plain")
	s.expectExit(inv, 0)
	s.expectStdoutBytes(inv, bytes.TrimSuffix(shown, []byte("\n")))

	// rotate of a missing key: exit 5, remediation-bearing message.
	inv = s.run("rotate-missing", "rotate", "GONE_KEY")
	s.expectExit(inv, 5)
	s.expectStdoutEmpty(inv)
	s.expectStderrContains(inv, "Nothing to rotate")

	// doctor on the healthy workspace: exit 0, zero failed checks.
	inv = s.run("doctor", "doctor")
	s.expectExit(inv, 0)
	s.expectStdoutContains(inv, "0 failed")

	inv = s.run("doctor-json", "doctor", "--format", "json")
	s.expectExit(inv, 0)
	obj = s.expectJSONObject(inv)
	if obj != nil {
		checks, ok := obj["checks"].([]any)
		if !ok || len(checks) == 0 {
			s.violate(inv, "doctor json checks array", fmt.Sprint(obj["checks"]))
		} else {
			for _, c := range checks {
				m, _ := c.(map[string]any)
				status, _ := m["status"].(string)
				if status != "pass" && status != "warn" {
					s.violate(inv, "every doctor check passes or warns on a healthy workspace",
						fmt.Sprintf("check %v status %q", m["name"], status))
				}
			}
		}
	}

	// scan on a clean tree: exit 0, stdout empty (report-only on findings).
	// The provider file is gitignored — tracked files are the scan surface.
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".secrets*.yaml\n"), 0o600))
	inv = s.run("scan-clean", "scan")
	s.expectExit(inv, 0)
	s.expectStdoutEmpty(inv)
	s.expectStderrContains(inv, "No leaks")

	// scan with a tracked file carrying a managed value: exit 10
	// (ExitLeakFound), finding on stdout with key and file, status on stderr.
	canary := "canary-" + strings.ToLower(strings.Repeat("d", 24))
	inv = s.run("set-canary", "set", "SCAN_KEY", canary)
	s.expectExit(inv, 0)
	leak := filepath.Join(dir, "leak.txt")
	require.NoError(t, os.WriteFile(leak, []byte("token = "+canary+"\n"), 0o600))
	git := func(args ...string) {
		cmd := exec.CommandContext(context.Background(), "git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	git("add", "leak.txt")
	inv = s.run("scan-leak", "scan")
	s.expectExit(inv, 10)
	s.expectStdoutContains(inv, "SCAN_KEY")
	s.expectStdoutContains(inv, "leak.txt")
	s.expectStderrContains(inv, "found")
	inv = s.run("scan-leak-json", "scan", "--format", "json")
	s.expectExit(inv, 10)

	// Non-interactive delete: without --confirm at a non-TTY stdin the command
	// must cancel promptly (no prompt, no hang) and not mutate.
	inv = s.run("delete-no-confirm", "delete", "SCAN_KEY")
	s.expectExit(inv, 0)
	inv = s.run("get-after-cancelled-delete", "get", "SCAN_KEY", "--plain")
	s.expectExit(inv, 0)
	s.expectStdoutBytes(inv, []byte(canary))

	// delete --confirm (table): status on stderr, key gone (exit 5 after).
	inv = s.run("delete-confirm", "delete", "SCAN_KEY", "--confirm")
	s.expectExit(inv, 0)
	s.expectStdoutEmpty(inv)
	s.expectStderrContains(inv, "Deleted SCAN_KEY")
	inv = s.run("get-deleted", "get", "SCAN_KEY")
	s.expectExit(inv, 5)

	// delete --format json: documented payload on stdout.
	inv = s.run("set-deljson", "set", "DELJSON_KEY", "x")
	s.expectExit(inv, 0)
	inv = s.run("delete-json", "delete", "DELJSON_KEY", "--confirm", "--format", "json")
	s.expectExit(inv, 0)
	obj = s.expectJSONObject(inv)
	if obj != nil {
		s.expectJSONFieldString(obj, inv.name, "key", "DELJSON_KEY")
		s.expectJSONFieldBool(obj, inv.name, "deleted", true)
	}

	// Usage errors (cobra arg validation): exit 1 with the error envelope —
	// the code field must agree even for unclassified errors.
	inv = s.run("set-no-args", "set")
	s.expectExit(inv, 1)
	inv = s.run("set-no-args-json", "set", "--format", "json")
	s.expectExit(inv, 1)
	s.expectEnvelope(inv, 1)

	s.failOnViolations()
}
