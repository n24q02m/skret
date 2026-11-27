//go:build !windows

package exec_test

import (
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startWaitTerm runs a child that exits 42 on SIGTERM and waits until it is
// ready, returning its output buffer and the channel RunFiltered reports on.
func startWaitTerm(t *testing.T) (*syncBuffer, <-chan error) {
	t.Helper()
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() {
		done <- skexec.RunFiltered(os.Args[0], []string{os.Args[0]}, childEnv("waitterm"), out, io.Discard)
	}()
	require.Eventually(t, func() bool { return strings.Contains(out.String(), "ready") },
		20*time.Second, 10*time.Millisecond, "child never became ready")
	return out, done
}

func waitResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(20 * time.Second):
		t.Fatal("RunFiltered did not return")
		return nil
	}
}

func TestRunFiltered_RelaysSIGTERM(t *testing.T) {
	out, done := startWaitTerm(t)
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))

	err := waitResult(t, done)
	assert.Equal(t, 42, skexec.ExitCode(err))
	assert.Contains(t, out.String(), "terminated")
}

func TestRunFiltered_RelaysSIGINTWithoutForegroundTerminal(t *testing.T) {
	defer skexec.SetKeyboardSignalsReachChild(func() bool { return false })()
	_, done := startWaitTerm(t)
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGINT))

	var coder interface{ ExitCode() int }
	err := waitResult(t, done)
	require.ErrorAs(t, err, &coder)
	assert.Equal(t, 128+int(syscall.SIGINT), coder.ExitCode())
}

// In the terminal's foreground group a keyboard SIGINT already reached the
// child directly, so relaying it would deliver it twice.
func TestRunFiltered_SkipsKeyboardSignalsTheTerminalDelivered(t *testing.T) {
	defer skexec.SetKeyboardSignalsReachChild(func() bool { return true })()
	out, done := startWaitTerm(t)
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGINT))
	time.Sleep(300 * time.Millisecond)
	assert.NotContains(t, out.String(), "terminated")

	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))
	assert.Equal(t, 42, skexec.ExitCode(waitResult(t, done)))
}
