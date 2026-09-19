package agente2e_test

// The self-check: the harness must actually catch contract violations. Each
// case builds a deliberately broken skret stand-in, runs the same compact
// workload the harness uses, and requires the violation report to name the
// broken promise. The baseline stand-in implements the contract correctly and
// must produce zero violations — proving a red report below comes from the
// intentional breakage, not from a workload bug.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeSource is a minimal skret stand-in. It answers only the invocations the
// compact workload makes, driven by SKRET_FAKE_MODE:
//
//	baseline              implements the contract correctly
//	wrong-exit            get of a missing key exits 3 (contract: 5)
//	envelope-code-mismatch  envelope says code 2 while exiting 5
//	no-envelope           missing-key error carries prose, not the envelope
//	stdout-on-stderr      get --plain prints the value on stderr
//	byte-inexact          get --plain appends a newline
//	prompt-hang           delete without --confirm blocks like a TTY prompt
const fakeSource = `package main

import (
	"fmt"
	"os"
	"time"
)

func envelope(code int) {
	fmt.Fprintf(os.Stderr, "{\n  \"error\": \"fake error for mode %s\",\n  \"code\": %d\n}\n", os.Getenv("SKRET_FAKE_MODE"), code)
}

func main() {
	mode := os.Getenv("SKRET_FAKE_MODE")
	args := os.Args[1:]
	if len(args) == 0 {
		os.Exit(1)
	}
	switch args[0] {
	case "get":
		if len(args) > 1 && args[1] == "MISSING_KEY" {
			for i, a := range args {
				if a == "--format" && i+1 < len(args) && args[i+1] == "json" {
					if mode == "no-envelope" {
						fmt.Fprintln(os.Stderr, "Error: secret MISSING_KEY not found")
						os.Exit(5)
					}
					code := 5
					if mode == "envelope-code-mismatch" {
						code = 2
					}
					envelope(code)
					os.Exit(5)
				}
			}
			if mode == "wrong-exit" {
				fmt.Fprintln(os.Stderr, "not found")
				os.Exit(3)
			}
			fmt.Fprintln(os.Stderr, "MISSING_KEY not found")
			os.Exit(5)
		}
		if mode == "stdout-on-stderr" {
			fmt.Fprintln(os.Stderr, "value")
			os.Exit(0)
		}
		if mode == "byte-inexact" {
			fmt.Println("value")
			os.Exit(0)
		}
		fmt.Print("value")
		os.Exit(0)
	case "delete":
		if mode == "prompt-hang" {
			time.Sleep(60 * time.Second)
		}
		fmt.Fprintln(os.Stderr, "Cancelled.")
		os.Exit(0)
	}
	os.Exit(1)
}
`

// runWorkload is the compact contract workload the self-check drives against
// the stand-in: byte-exact read, documented exit code, JSON envelope, and the
// no-TTY delete cancel. The full session in session_test.go covers much more;
// these four steps span the four violation classes the harness exists for.
func runWorkload(s *session) {
	inv := s.run("get-plain", "get", "K", "--plain")
	s.expectExit(inv, 0)
	s.expectStdoutBytes(inv, []byte("value"))

	inv = s.run("get-missing", "get", "MISSING_KEY")
	s.expectExit(inv, 5)

	inv = s.run("get-missing-json", "get", "MISSING_KEY", "--format", "json")
	s.expectExit(inv, 5)
	s.expectEnvelope(inv, 5)

	inv = s.run("delete-cancel", "delete", "K")
	s.expectExit(inv, 0)
}

func buildFake(t *testing.T, dir string) string {
	t.Helper()
	src := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(src, []byte(fakeSource), 0o600))
	name := "fake-skret"
	if runtime.GOOS == "windows" {
		name = "fake-skret.exe"
	}
	bin := filepath.Join(dir, name)
	out, err := exec.CommandContext(context.Background(), "go", "build", "-o", bin, src).CombinedOutput()
	require.NoError(t, err, "build fake skret: %s", out)
	return bin
}

func violationsText(vs []violation) string {
	var b strings.Builder
	for _, v := range vs {
		b.WriteString(v.String())
		b.WriteString("\n")
	}
	return b.String()
}

func TestSelfCheck_BrokenContractsAreCaught(t *testing.T) {
	if testing.Short() {
		t.Skip("self-check builds helper binaries; skipped in -short mode")
	}
	// The prompt-hang case needs the watchdog, not the full 30s budget.
	origTimeout := perInvocationTimeout
	perInvocationTimeout = 2 * time.Second
	t.Cleanup(func() { perInvocationTimeout = origTimeout })
	bin := buildFake(t, t.TempDir())

	// Baseline: a contract-correct stand-in passes the workload cleanly. If
	// this ever reds, the workload (not the product) is broken.
	s := newSession(t, bin, t.TempDir())
	t.Setenv("SKRET_FAKE_MODE", "baseline")
	runWorkload(s)
	require.Empty(t, s.violations, "baseline stand-in must satisfy the contract; got:\n%s", violationsText(s.violations))

	for _, tc := range []struct {
		mode         string
		wantMentions []string // substrings the violation report must contain
	}{
		{"wrong-exit", []string{`step "get-missing"`, "exit code 5", "exit code 3"}},
		{"envelope-code-mismatch", []string{`step "get-missing-json"`, `envelope "code" == 5`, "envelope code 2"}},
		{"no-envelope", []string{`step "get-missing-json"`, "unparseable stderr"}},
		{"stdout-on-stderr", []string{`step "get-plain"`, "stdout bytes"}},
		{"byte-inexact", []string{`step "get-plain"`, "stdout bytes"}},
		{"prompt-hang", []string{`step "delete-cancel"`, "timeout"}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			s := newSession(t, bin, t.TempDir())
			t.Setenv("SKRET_FAKE_MODE", tc.mode)
			runWorkload(s)
			require.NotEmpty(t, s.violations,
				"mode %q must be caught: the harness passed a broken contract", tc.mode)
			report := violationsText(s.violations)
			for _, want := range tc.wantMentions {
				require.Contains(t, report, want,
					"violation report for %q must name the broken promise", tc.mode)
			}
			if tc.mode != "prompt-hang" {
				require.NotContains(t, report, "timeout",
					"only the prompt-hang mode may time out")
			}
		})
	}
}

// TestSelfCheck_BinaryOverrideHook documents the extension point: the harness
// runs unchanged against any binary handed to it via SKRET_AGENT_E2E_BINARY.
func TestSelfCheck_BinaryOverrideHook(t *testing.T) {
	bin := buildFake(t, t.TempDir())
	t.Setenv(binaryEnvVar, bin)
	require.Equal(t, bin, buildSkret(t), "the override must be honored verbatim")

	t.Setenv("SKRET_FAKE_MODE", "wrong-exit")
	s := newSession(t, bin, t.TempDir())
	runWorkload(s)
	require.NotEmpty(t, s.violations,
		"an overridden binary violating the contract must be caught")
}
