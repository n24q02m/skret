package auth

import (
	"os"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestMain sets SKRET_NO_BROWSER so any OpenBrowser call never launches a real
// browser, and switches go-keyring to its in-memory mock so no test ever
// touches the real OS keychain (which on a headless/locked macOS runner makes
// the `security` CLI hang). Belt-and-suspenders on top of per-test mocking.
func TestMain(m *testing.M) {
	_ = os.Setenv("SKRET_NO_BROWSER", "1")
	keyring.MockInit()
	os.Exit(m.Run())
}
