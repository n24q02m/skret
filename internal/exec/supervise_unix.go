//go:build !windows

package exec

import (
	osexec "os/exec"
	"syscall"
	"time"
)

// setProcAttr makes the child lead its own process group so we can signal the
// whole tree (negative pid) rather than just the immediate child.
func setProcAttr(c *osexec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminate sends SIGTERM to the child's process group, escalating to SIGKILL
// if it does not exit within grace. It returns once the child exits or grace
// elapses. It never closes done, and re-delivers any value it observes so a
// caller waiting on Done() still sees the child's exit.
func terminate(c *osexec.Cmd, done chan error, grace time.Duration) {
	if c.Process == nil {
		return
	}
	// Negative pid targets the whole process group. Ignore ESRCH (already gone).
	if err := syscall.Kill(-c.Process.Pid, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
		return
	}
	select {
	case err := <-done:
		done <- err // re-deliver so the caller's Done() still observes the exit
		return
	case <-time.After(grace):
		_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
	}
}
