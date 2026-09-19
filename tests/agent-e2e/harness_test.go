package agente2e_test

// The agent-contract harness: a scripted agent session that drives a skret
// binary exactly the way an unattended agent or CI script would, and fails on
// any deviation from the documented contract (docs/guide/agents.md):
//
//   - documented exit codes per failure class,
//   - the JSON error envelope on stderr ({"error", "code"} with code == exit),
//   - byte-exact stdout for data (get --plain, rotate --show),
//   - stdout == data / stderr == status discipline,
//   - non-interactive behavior with no TTY (prompts must not hang).
//
// The binary under test defaults to a fresh build of ./cmd/skret and can be
// pointed at any build via SKRET_AGENT_E2E_BINARY (the documented hook point
// for testing release artifacts or a future LLM-driven variant).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const binaryEnvVar = "SKRET_AGENT_E2E_BINARY"

// perInvocationTimeout bounds every skret invocation. A command that blocks
// waiting for a TTY prompt (the exact non-interactive violation an agent
// cannot recover from) surfaces as a timeout violation instead of wedging CI.
// A var so the self-check can shrink it; restore after overriding.
var perInvocationTimeout = 30 * time.Second

// invocation is one recorded skret run: what was asked, and exactly what came
// back on each stream. stdout/stderr are kept as raw bytes throughout — the
// contract is byte-exact, so nothing may pass through string trimming before
// an assertion sees it.
type invocation struct {
	name   string
	args   []string
	exit   int
	stdout []byte
	stderr []byte
}

type violation struct {
	step string
	want string
	got  string
}

func (v violation) String() string {
	return fmt.Sprintf("step %q:\n  want: %s\n  got:  %s", v.step, v.want, v.got)
}

// session drives one skret workspace (a temp dir with its own git repo and
// local provider files) and accumulates contract violations. Assertions never
// abort the session: an agent evaluating skret would keep going, and reporting
// every violation in one pass makes the harness output actionable.
type session struct {
	t           *testing.T
	binary      string
	dir         string
	stdin       []byte
	extraEnv    []string
	invocations []invocation
	violations  []violation
}

func newSession(t *testing.T, binary, dir string) *session {
	t.Helper()
	return &session{t: t, binary: binary, dir: dir}
}

// run executes one skret invocation and records it. It never fails the test
// directly; expectations are declared with the expect* helpers so the
// violation report names every broken promise, not just the first.
func (s *session) run(name string, args ...string) invocation {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), perInvocationTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.binary, args...)
	cmd.Dir = s.dir
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb")
	cmd.Env = append(cmd.Env, s.extraEnv...)
	if s.stdin != nil {
		cmd.Stdin = bytes.NewReader(s.stdin)
		s.stdin = nil // stdin is per-invocation; never leak into later steps
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	inv := invocation{name: name, args: args}
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		s.violations = append(s.violations, violation{
			step: name,
			want: "completion within " + perInvocationTimeout.String() + " (non-interactive contract)",
			got:  "timeout — command blocked, most likely waiting for a TTY prompt",
		})
		inv.exit = -1
		inv.stdout = stdout.Bytes()
		inv.stderr = stderr.Bytes()
		s.invocations = append(s.invocations, inv)
		return inv
	}
	if err != nil {
		inv.exit = exitCodeOf(err)
	} else {
		inv.exit = 0
	}
	inv.stdout = stdout.Bytes()
	inv.stderr = stderr.Bytes()
	s.invocations = append(s.invocations, inv)
	return inv
}

func exitCodeOf(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// withStdin pipes b to the next invocation only (set --from-stdin, scan fixtures).
func (s *session) withStdin(b []byte) *session {
	s.stdin = b
	return s
}

func (s *session) expectExit(inv invocation, code int) {
	s.t.Helper()
	if inv.exit != code {
		s.violate(inv, fmt.Sprintf("exit code %d", code),
			fmt.Sprintf("exit code %d (stderr: %q)", inv.exit, inv.stderr))
	}
}

func (s *session) expectStdoutBytes(inv invocation, want []byte) {
	s.t.Helper()
	if !bytes.Equal(inv.stdout, want) {
		s.violate(inv, fmt.Sprintf("stdout bytes %q", want), fmt.Sprintf("stdout bytes %q", inv.stdout))
	}
}

func (s *session) expectStdoutContains(inv invocation, sub string) {
	s.t.Helper()
	if !bytes.Contains(inv.stdout, []byte(sub)) {
		s.violate(inv, fmt.Sprintf("stdout containing %q", sub), fmt.Sprintf("stdout %q", inv.stdout))
	}
}

func (s *session) expectStdoutEmpty(inv invocation) {
	s.t.Helper()
	if len(inv.stdout) != 0 {
		s.violate(inv, "empty stdout (data did not belong on this stream)",
			fmt.Sprintf("stdout %q", inv.stdout))
	}
}

func (s *session) expectStderrEmpty(inv invocation) {
	s.t.Helper()
	if len(inv.stderr) != 0 {
		s.violate(inv, "empty stderr (status did not belong on this stream)",
			fmt.Sprintf("stderr %q", inv.stderr))
	}
}

func (s *session) expectStderrContains(inv invocation, sub string) {
	s.t.Helper()
	if !bytes.Contains(inv.stderr, []byte(sub)) {
		s.violate(inv, fmt.Sprintf("stderr containing %q", sub), fmt.Sprintf("stderr %q", inv.stderr))
	}
}

// expectEnvelope asserts the documented JSON error envelope on stderr: a
// parseable object whose "error" is a non-empty string and whose "code" is a
// number that equals both the expected and the actual exit code. "remediation"
// is optional; when present it must be a non-empty string.
func (s *session) expectEnvelope(inv invocation, code int) {
	s.t.Helper()
	if len(inv.stdout) != 0 {
		s.violate(inv, "empty stdout on error", fmt.Sprintf("stdout %q", inv.stdout))
	}
	var env map[string]any
	dec := json.NewDecoder(bytes.NewReader(inv.stderr))
	dec.UseNumber()
	if err := dec.Decode(&env); err != nil {
		s.violate(inv, fmt.Sprintf("JSON error envelope on stderr (exit %d)", code),
			fmt.Sprintf("unparseable stderr: %q (%v)", inv.stderr, err))
		return
	}
	msg, ok := env["error"].(string)
	if !ok || msg == "" {
		s.violate(inv, `envelope field "error" as non-empty string`,
			fmt.Sprintf("envelope %v", env))
	}
	gotCode, ok := env["code"].(json.Number)
	if !ok {
		s.violate(inv, `envelope field "code" as number`, fmt.Sprintf("envelope %v", env))
		return
	}
	if n, err := gotCode.Int64(); err != nil || int(n) != code {
		s.violate(inv, fmt.Sprintf(`envelope "code" == %d`, code),
			fmt.Sprintf("envelope code %s", gotCode.String()))
	}
	if int(gotNumeric(gotCode)) != inv.exit {
		s.violate(inv, "envelope code agrees with the actual exit code",
			fmt.Sprintf("envelope code %s vs exit %d", gotCode.String(), inv.exit))
	}
	if rem, present := env["remediation"]; present {
		if remStr, ok := rem.(string); !ok || remStr == "" {
			s.violate(inv, `optional "remediation" as non-empty string when present`,
				fmt.Sprintf("remediation %v", rem))
		}
	}
}

func gotNumeric(n json.Number) int64 {
	v, _ := n.Int64()
	return v
}

// expectJSONObject parses a success payload from stdout and hands it back for
// field-level checks. It records a violation and returns nil on any parse
// failure so callers can chain without re-checking.
func (s *session) expectJSONObject(inv invocation) map[string]any {
	s.t.Helper()
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(inv.stdout))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		s.violate(inv, "JSON object on stdout", fmt.Sprintf("stdout %q (%v)", inv.stdout, err))
		return nil
	}
	return obj
}

func (s *session) expectJSONArray(inv invocation) []any {
	s.t.Helper()
	var arr []any
	if err := json.Unmarshal(inv.stdout, &arr); err != nil {
		s.violate(inv, "JSON array on stdout", fmt.Sprintf("stdout %q (%v)", inv.stdout, err))
		return nil
	}
	return arr
}

// violateStep records a violation against a named step (used by helpers that
// receive the step name rather than the full invocation).
func (s *session) violateStep(name, want, got string) {
	s.t.Helper()
	s.violations = append(s.violations, violation{step: name, want: want, got: got})
}

func (s *session) expectJSONFieldString(obj map[string]any, inv, field, want string) {
	s.t.Helper()
	got, ok := obj[field].(string)
	if !ok || got != want {
		s.violateStep(inv, fmt.Sprintf("JSON field %q == %q", field, want),
			fmt.Sprintf("field %q == %v", field, obj[field]))
	}
}

func (s *session) expectJSONFieldBool(obj map[string]any, inv, field string, want bool) {
	s.t.Helper()
	got, ok := obj[field].(bool)
	if !ok || got != want {
		s.violateStep(inv, fmt.Sprintf("JSON field %q == %v", field, want),
			fmt.Sprintf("field %q == %v", field, obj[field]))
	}
}

func (s *session) violate(inv invocation, want, got string) {
	s.t.Helper()
	s.violations = append(s.violations, violation{step: inv.name, want: want, got: got})
}

// failOnViolations converts the accumulated report into a test failure, one
// line per violation, so a red run reads like a contract diff.
func (s *session) failOnViolations() {
	s.t.Helper()
	if len(s.violations) == 0 {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "agent contract violated in %d place(s):\n", len(s.violations))
	for _, v := range s.violations {
		b.WriteString("  - " + v.String() + "\n")
	}
	s.t.Fatal(b.String())
}

// buildSkret returns the binary under test: SKRET_AGENT_E2E_BINARY when set,
// otherwise a fresh build of ./cmd/skret. Building per test-binary (not per
// test) mirrors tests/e2e and keeps every assertion on the current tree.
func buildSkret(t *testing.T) string {
	t.Helper()
	if p := os.Getenv(binaryEnvVar); p != "" {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s=%s is not accessible: %v", binaryEnvVar, p, err)
		}
		return p
	}
	name := "skret"
	if runtime.GOOS == "windows" {
		name = "skret.exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	if err := exec.CommandContext(context.Background(), "go", "build", "-o", bin, "../../cmd/skret").Run(); err != nil {
		t.Fatalf("build ./cmd/skret: %v", err)
	}
	return bin
}
