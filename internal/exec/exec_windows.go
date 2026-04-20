//go:build windows

package exec

import (
	"context"
	"os"
	"os/exec"
)

// Run executes a command as a child process on Windows,
// because process replacement (syscall.Exec) is not supported.
// A Background context is used because the CLI `run` subcommand inherits
// the parent's lifetime; OS signals (Ctrl-C) reach the child via the
// process group, not through context cancellation.
func Run(binary string, args []string, env []string) error {
	c := exec.CommandContext(context.Background(), binary, args[1:]...)
	c.Env = env
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
