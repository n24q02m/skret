package cli

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestMain switches go-keyring to its in-memory mock so CLI tests that reach
// auth.NewStore() (via command execution) never probe the real OS keyring.
// On Windows the real Credential Manager round-trip can stall under the
// parallel `go test ./...` load and trip the 3s availability timeout, making
// the suite flaky; the mock makes backend selection deterministic.
func TestMain(m *testing.M) {
	// When spawned as a child by the run --watch integration test, act as a
	// fast-exiting command instead of re-running the suite. The value is the
	// exit code so tests can exercise both the clean and non-zero exit paths.
	if code, ok := os.LookupEnv("SKRET_RUN_CHILD"); ok {
		n, _ := strconv.Atoi(code)
		os.Exit(n)
	}

	// Reference-resolution run tests spawn this binary as the child command;
	// this branch dumps one inherited env var to a file so the parent can
	// assert on the injected value portably (no shell assumptions).
	if out := os.Getenv("SKRET_RUN_ENV_DUMP"); out != "" {
		name := os.Getenv("SKRET_RUN_ENV_NAME")
		_ = os.WriteFile(out, []byte(os.Getenv(name)), 0o600)
		os.Exit(0)
	}

	// run --redact tests spawn this binary as a command that prints a file
	// (stdout one byte per write, stderr in one write), then optionally the
	// value of one inherited env var on stdout, and exits with a chosen code.
	if file := os.Getenv("SKRET_RUN_PRINT_FILE"); file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			os.Exit(99)
		}
		for i := range data {
			_, _ = os.Stdout.Write(data[i : i+1])
		}
		_, _ = os.Stderr.Write(data)
		if name := os.Getenv("SKRET_RUN_PRINT_ENV"); name != "" {
			_, _ = os.Stdout.WriteString(os.Getenv(name))
		}
		n, _ := strconv.Atoi(os.Getenv("SKRET_RUN_PRINT_EXIT"))
		os.Exit(n)
	}

	keyring.MockInit()

	// Stub AWS probe for all CLI tests to avoid network calls and credential dependencies.
	awsLivenessProbe = func(context.Context) error { return nil }

	os.Exit(m.Run())
}
