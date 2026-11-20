//go:build !windows

package exec_test

import (
	"errors"
	"os"
	osexec "os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A child that ignores SIGTERM is hard-killed once the grace period runs
// out, so Terminate cannot hang on an uncooperative process.
func TestSupervise_TerminateEscalatesToKill(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	child, err := skexec.Supervise(os.Args[0], []string{os.Args[0]},
		append(childEnv("ignoreterm"), "SKRET_TEST_READY="+ready))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		_, statErr := os.Stat(ready)
		return statErr == nil
	}, 20*time.Second, 10*time.Millisecond, "child never reported that it ignores SIGTERM")

	start := time.Now()
	child.Terminate(200 * time.Millisecond)

	select {
	case waitErr := <-child.Done():
		assert.Less(t, time.Since(start), 25*time.Second, "child should stop well before the 30s sleep")
		var exitErr *osexec.ExitError
		require.True(t, errors.As(waitErr, &exitErr), "unexpected wait error: %v", waitErr)
		status, ok := exitErr.Sys().(syscall.WaitStatus)
		require.True(t, ok)
		assert.Equal(t, syscall.SIGKILL, status.Signal(), "an ignored SIGTERM must end in SIGKILL")
	case <-time.After(25 * time.Second):
		t.Fatal("child did not exit after Terminate")
	}
}
