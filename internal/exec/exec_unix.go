//go:build !windows

package exec

import (
	"syscall"
)

// Run executes a command with process replacement (syscall.Exec) on Unix.
func Run(binary string, args, env []string) error {
	return syscall.Exec(binary, args, env)
}
