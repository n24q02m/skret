//go:build windows

package exec

import (
	osexec "os/exec"
	"time"
)

// setProcAttr is a no-op on Windows, which lacks POSIX process groups.
func setProcAttr(_ *osexec.Cmd) {}

// terminate stops the child. Windows has no SIGTERM, so this is a best-effort
// hard kill bounded by grace. Kill is immediate on Windows; the grace select
// just bounds the wait for Wait() to observe the exit. It re-delivers any value
// it observes so a caller waiting on Done() still sees the child's exit.
func terminate(c *osexec.Cmd, done chan error, grace time.Duration) {
	if c.Process == nil {
		return
	}
	_ = c.Process.Kill()
	select {
	case err := <-done:
		done <- err // re-deliver so the caller's Done() still observes the exit
	case <-time.After(grace):
	}
}
