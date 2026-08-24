//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package secretlaunch

import (
	"os"
	"os/exec"
)

func configureProcessGroup(_ *exec.Cmd) error { return nil }

func applyChildUser(_ *exec.Cmd, value string) error {
	if value != "current" {
		return fail(ErrChild)
	}
	return nil
}

func signalProcessTree(process *os.Process, signal os.Signal) error {
	if process == nil {
		return fail(ErrChild)
	}
	return process.Signal(signal)
}

func killProcessTree(process *os.Process) error {
	if process == nil {
		return fail(ErrChild)
	}
	return process.Kill()
}

func disableDumps() error { return nil }
