package exec

import (
	"context"
	"errors"
	"io"
	"os"
	osexec "os/exec"
	"os/signal"
	"time"
)

// filteredWaitDelay bounds how long RunFiltered keeps draining output after
// the child exits, in case a process the child left behind still holds the
// output pipes open.
var filteredWaitDelay = 5 * time.Second

// RunFiltered runs args[0] (already resolved to binary) as a child process
// with env and the parent's stdin, sending its stdout and stderr to the given
// writers instead of the parent's file descriptors, so the caller can rewrite
// the output (`run --redact`). Unlike Run it never replaces the skret process.
//
// Termination signals sent to skret are relayed to the child, and skret keeps
// waiting until the child exits. On Unix, keyboard signals (SIGINT, SIGQUIT)
// and SIGHUP are not relayed when skret is in the terminal's foreground
// process group: the child shares that group, so the terminal already
// delivered them. On Windows the console delivers Ctrl+C and Ctrl+Break to the
// child directly; skret only catches them so it can finish draining output.
//
// The error is nil when the child exits 0, the child's *exec.ExitError when it
// exits non-zero, and (on Unix) an error whose ExitCode() is 128+signal when a
// signal killed it, the code a shell would report.
func RunFiltered(binary string, args, env []string, stdout, stderr io.Writer) error {
	c := osexec.CommandContext(context.Background(), binary, args[1:]...)
	c.Env = env
	c.Stdin = os.Stdin
	c.Stdout = stdout
	c.Stderr = stderr
	c.WaitDelay = filteredWaitDelay

	sigCh := make(chan os.Signal, 8)
	signal.Notify(sigCh, relayedSignals...)
	defer signal.Stop(sigCh)
	if err := c.Start(); err != nil {
		return err
	}

	stop := make(chan struct{})
	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		for {
			select {
			case sig := <-sigCh:
				relay(c.Process, sig)
			case <-stop:
				return
			}
		}
	}()

	err := c.Wait()
	close(stop)
	<-relayDone
	if errors.Is(err, osexec.ErrWaitDelay) {
		return nil // the child exited 0; only a leftover process held the pipes
	}
	var exitErr *osexec.ExitError
	if errors.As(err, &exitErr) {
		return childExit(exitErr)
	}
	return err
}
