// internal/cli/shellquote_fidelity_test.go
package cli

import (
	"os/exec"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A POSIX shell must reproduce the exact bytes of `printf %s <quoted>`.
// Skip on Windows (no POSIX sh guaranteed). shellSingleQuote is the unit under test.
func TestShellSingleQuote_RoundTripViaSh(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX sh on Windows runner")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not found")
	}
	for _, v := range []string{`$HOME`, `it's`, "a\nb", `"'` + "`", `a\b`, `${X}`, ``, `  sp  `} {
		out, err := exec.Command(sh, "-c", "printf %s "+shellSingleQuote(v)).Output()
		require.NoError(t, err)
		assert.Equal(t, v, string(out), "shell must reproduce exact bytes")
	}
}
