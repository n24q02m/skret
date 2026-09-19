package agente2e_test

// TestMain doubles as the child process used by the `run --` assertions: when
// skret injects secrets and execs this binary, the child mode env vars below
// are present and the binary acts as a minimal probe command instead of a test
// runner (same re-exec pattern as internal/cli's own run tests, kept here so
// the harness has no shell dependency on any platform).

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestMain(m *testing.M) {
	switch os.Getenv("AGENT_E2E_CHILD_MODE") {
	case "print-env":
		fmt.Println(os.Getenv(os.Getenv("AGENT_E2E_CHILD_ENV")))
		os.Exit(0)
	case "exit":
		code, _ := strconv.Atoi(os.Getenv("AGENT_E2E_CHILD_EXIT"))
		os.Exit(code)
	}
	os.Exit(m.Run())
}
