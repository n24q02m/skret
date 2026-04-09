//go:build windows

package exec

import (
	"os"
	"os/exec"
)

// Run executes a command as a child process on Windows,
// because process replacement (syscall.Exec) is not supported.
func Run(binary string, args []string, env []string) error {
	c := exec.Command(binary, args[1:]...)
	c.Env = env
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
