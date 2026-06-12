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

	keyring.MockInit()

	// Stub AWS probe for all CLI tests to avoid network calls and credential dependencies.
	awsLivenessProbe = func(context.Context) error { return nil }

	os.Exit(m.Run())
}
