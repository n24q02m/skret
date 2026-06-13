package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/n24q02m/skret/internal/config"
	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

// supervisor is the subset of *exec.Child the watch loop needs (seam for tests).
type supervisor interface {
	Done() <-chan error
	Terminate(grace time.Duration)
}

// watchDeps bundles the injectable seams the watch loop runs over, so the loop
// is unit-testable without real processes, clocks, or signals.
type watchDeps struct {
	fingerprint func(ctx context.Context) (string, error)
	list        func(ctx context.Context) ([]*provider.Secret, error)
	buildEnv    func([]*provider.Secret) []string
	spawn       func(env []string) (supervisor, error)
	tick        <-chan time.Time
	signals     <-chan os.Signal
	grace       time.Duration
	out         io.Writer
}

// watchLoop runs an already-spawned child, restarting it when fingerprint
// changes, until the child exits on its own or a signal arrives. Returns the
// child's last exit code.
func watchLoop(ctx context.Context, d watchDeps, child supervisor, initialFP string) (int, error) {
	fp := initialFP
	for {
		select {
		case err := <-child.Done():
			return skexec.ExitCode(err), err // child exited on its own
		case <-d.signals:
			child.Terminate(d.grace)
			return 0, nil
		case <-d.tick:
			cur, err := d.fingerprint(ctx)
			if err != nil {
				continue // transient: keep child, retry next tick (do NOT kill on poll error)
			}
			if cur == fp {
				continue
			}
			fmt.Fprintln(d.out, "[skret] secrets changed - restarting")
			child.Terminate(d.grace)
			secrets, err := d.list(ctx)
			if err != nil {
				return 1, err
			}
			env := d.buildEnv(secrets)
			next, err := d.spawn(env)
			if err != nil {
				return 1, err
			}
			child = next
			fp = cur
		}
	}
}

// runWatch supervises args as a child subprocess that skret restarts whenever
// the provider's fingerprint changes, until the child exits or a signal arrives.
func runWatch(cmd *cobra.Command, p provider.SecretProvider, resolved *config.ResolvedConfig, args []string, secrets []*provider.Secret, env []string, interval time.Duration) error {
	_ = secrets // initial secrets already folded into env by the caller
	if interval < time.Second {
		interval = time.Second // guard
	}
	binary, err := osexec.LookPath(args[0])
	if err != nil {
		return skret.NewError(skret.ExitExecError, fmt.Sprintf("run: command not found: %s", args[0]), err)
	}
	ctx := context.Background()
	fp, err := p.Fingerprint(ctx, resolved.Path)
	if err != nil {
		return skret.NewError(skret.ExitProviderError, "run: fingerprint failed", err)
	}
	child, err := skexec.Supervise(binary, args, env)
	if err != nil {
		return skret.NewError(skret.ExitExecError, "run: failed to start command", err)
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	deps := watchDeps{
		fingerprint: func(c context.Context) (string, error) { return p.Fingerprint(c, resolved.Path) },
		list:        func(c context.Context) ([]*provider.Secret, error) { return p.List(c, resolved.Path) },
		buildEnv: func(s []*provider.Secret) []string {
			return skexec.BuildEnv(s, os.Environ(), resolved.Path, resolved.Exclude)
		},
		spawn:   func(e []string) (supervisor, error) { return skexec.Supervise(binary, args, e) },
		tick:    ticker.C,
		signals: sigCh,
		grace:   5 * time.Second,
		out:     cmd.ErrOrStderr(),
	}

	code, runErr := watchLoop(ctx, deps, child, fp)
	if runErr != nil {
		return skret.NewError(skret.ExitExecError, "runtime error", runErr)
	}
	if code != 0 {
		return skret.NewError(skret.ExitExecError, fmt.Sprintf("command exited with code %d", code), nil)
	}
	return nil
}
