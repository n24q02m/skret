//go:build !windows

package exec

import (
	"os"
	osexec "os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// relayedSignals are the signals RunFiltered catches and relays to the child.
var relayedSignals = []os.Signal{
	syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2,
}

// ttyPath is the controlling terminal of the calling process.
const ttyPath = "/dev/tty"

// keyboardSignalsReachChild reports whether the terminal delivers keyboard
// signals to the child on its own: true when skret (and so the child, which
// shares skret's process group) is the terminal's foreground process group.
var keyboardSignalsReachChild = func() bool { return isForegroundProcessGroup(ttyPath) }

// relay forwards sig to the child unless the terminal already delivered it.
func relay(p *os.Process, sig os.Signal) {
	if shouldRelay(sig) {
		_ = p.Signal(sig) // the child may already have exited
	}
}

func shouldRelay(sig os.Signal) bool {
	switch sig {
	case syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP:
		return !keyboardSignalsReachChild()
	}
	return true
}

// isForegroundProcessGroup reports whether the calling process's group is the
// foreground process group of the terminal at path.
func isForegroundProcessGroup(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false // no controlling terminal (CI, daemons, cron)
	}
	defer f.Close()
	fg, err := terminalProcessGroup(int(f.Fd()))
	if err != nil {
		return false // not a terminal
	}
	own, err := unix.Getpgid(0)
	return err == nil && fg == own
}

// signalExit is a child killed by a signal. ExitCode reports 128+signal, the
// status a shell reports for such a child, instead of exec's -1.
type signalExit struct {
	*osexec.ExitError
	code int
}

func (e *signalExit) ExitCode() int { return e.code }

func (e *signalExit) Unwrap() error { return e.ExitError }

func childExit(err *osexec.ExitError) error {
	if ws, ok := err.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return &signalExit{ExitError: err, code: 128 + int(ws.Signal())}
	}
	return err
}
