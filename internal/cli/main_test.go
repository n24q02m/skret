package cli

import (
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
	keyring.MockInit()
	os.Exit(m.Run())
}
