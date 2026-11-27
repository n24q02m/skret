//go:build windows

package exec

import (
	"os"
	osexec "os/exec"
)

// relayedSignals: Ctrl+C and Ctrl+Break are caught only so skret outlives the
// child and can finish draining its output; the console delivers them to the
// child itself.
var relayedSignals = []os.Signal{os.Interrupt}

// relay is a no-op on Windows: the console already delivered the event to
// every process attached to it, the child included.
func relay(*os.Process, os.Signal) {}

// childExit returns err unchanged: Windows exit codes need no translation.
func childExit(err *osexec.ExitError) error { return err }
