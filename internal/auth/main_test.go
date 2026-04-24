package auth

import (
	"os"
	"testing"
)

// TestMain sets SKRET_NO_BROWSER so any OpenBrowser call from an internal test
// (including paths where a flow's Opener was not overridden) never launches
// a real browser. Belt-and-suspenders on top of per-test flow.Opener mocking.
func TestMain(m *testing.M) {
	_ = os.Setenv("SKRET_NO_BROWSER", "1")
	os.Exit(m.Run())
}
