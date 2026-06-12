package exec

import (
	"context"
	"errors"
	"os"
	osexec "os/exec"
	"time"
)

// Child is a running supervised subprocess (used by `run --watch`, which must
// keep skret alive — unlike Run's process replacement on Unix).
type Child struct {
	cmd  *osexec.Cmd
	done chan error
}

// Supervise starts args[0] (already resolved to binary) as a child subprocess
// with env and the parent's stdio. It does NOT replace the skret process.
func Supervise(binary string, args []string, env []string) (*Child, error) {
	// CommandContext (vs Command) matches the package's noctx lint policy; a
	// Background context is used because the supervised child's lifetime is
	// managed explicitly via Terminate, not context cancellation.
	c := osexec.CommandContext(context.Background(), binary, args[1:]...)
	c.Env = env
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	setProcAttr(c) // platform-specific: own process group so we can signal the tree
	if err := c.Start(); err != nil {
		return nil, err
	}
	ch := &Child{cmd: c, done: make(chan error, 1)}
	go func() { ch.done <- c.Wait() }()
	return ch, nil
}

// Done receives the child's Wait() error exactly once, when it exits.
func (c *Child) Done() <-chan error { return c.done }

// Terminate asks the child to stop gracefully, escalating to a hard kill if it
// does not exit within grace. It returns after the child has exited or grace
// elapsed. It does not consume the Done() value: a caller waiting on Done()
// still observes the child's exit afterward.
func (c *Child) Terminate(grace time.Duration) {
	terminate(c.cmd, c.done, grace)
}

// ExitCode extracts a process exit code from a Wait() error: 0 for nil, the
// process's code for *osexec.ExitError, and 1 for any other non-nil error.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *osexec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 1
}
