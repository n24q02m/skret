//go:build !windows

package exec_test

import (
	"os"
	"os/exec"
	"testing"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/stretchr/testify/assert"
)

func TestRun(t *testing.T) {
	exe, err := os.Executable()
	assert.NoError(t, err)

	cmd := exec.Command(exe, "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")

	out, err := cmd.CombinedOutput()
	assert.NoError(t, err)
	assert.Equal(t, "SUCCESS\n", string(out))
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	// Use /usr/bin/echo which we verified exists
	err := skexec.Run("/usr/bin/echo", []string{"echo", "SUCCESS"}, os.Environ())
	if err != nil {
		os.Exit(1)
	}
	// Should never reach here because syscall.Exec replaces the process
	os.Exit(2)
}

func TestRun_Error(t *testing.T) {
	err := skexec.Run("/non/existent/binary", []string{"binary"}, os.Environ())
	assert.Error(t, err)
}
