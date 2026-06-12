package cli

import (
	"context"
	"os"
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
	// trivial fast-exiting command instead of re-running the suite.
	if os.Getenv("SKRET_RUN_CHILD") != "" {
		os.Exit(0)
	}

	keyring.MockInit()

	// Stub AWS probe for all CLI tests to avoid network calls and credential dependencies.
	awsLivenessProbe = func(context.Context) error { return nil }

	os.Exit(m.Run())
}
