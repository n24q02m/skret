package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"time"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/logging"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

func newRunCmd(opts *GlobalOpts) *cobra.Command {
	var watch bool
	var watchInterval time.Duration
	var noResolve bool
	var redactOutput bool
	var redactMinLength int
	cmd := &cobra.Command{
		Use:   "run -- <command> [args...]",
		Short: "Run a command with secrets injected as environment variables",
		Long: `Run a command with all secrets injected as environment variables.

Values are injected verbatim, except three bytes that an OS environment cannot
carry: NUL and CR are dropped and LF is replaced with a space (see the
value-fidelity guide). ${KEY} references between secrets are resolved before
injection; use --no-resolve to inject raw stored values. Use --watch to
auto-restart the command when a secret changes.

Use --redact to mask secrets in the command's output: its stdout and stderr
pass through a filter that replaces every loaded secret value (including
multi-line values and their base64 and URL-encoded forms) and token-shaped
strings with [REDACTED]. The command then writes to pipes instead of the
terminal, so programs that check for a TTY may disable colour, progress bars
or line buffering. Values shorter than --redact-min-length are not masked.

With --redact, SIGTERM, SIGUSR1 and SIGUSR2 sent to skret are relayed to the
command. SIGINT, SIGQUIT and SIGHUP are relayed only when skret is not in the
terminal's foreground process group, because in the foreground the terminal
already sends them to the command. So in the foreground, kill -INT (or -QUIT,
-HUP) sent to skret's own PID is not relayed: to stop the command from a
script, send SIGTERM, or signal the whole process group (kill -INT -<pgid>).`,
		Example: `  skret run -- make deploy
  skret run -- ./server
  skret run --watch -- make up-prod
  skret run --redact -- ./ci-script.sh`,
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return skret.NewError(skret.ExitValidationError, "run: command required after --", nil)
			}
			if redactOutput && watch {
				return skret.NewError(skret.ExitValidationError, "run: --redact cannot be combined with --watch", nil)
			}
			if redactOutput && redactMinLength < 1 {
				return skret.NewError(skret.ExitValidationError, "run: --redact-min-length must be at least 1", nil)
			}

			resolved, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer p.Close()
			warnIfPathMangled(cmd, resolved)

			ctx := context.Background()
			secrets, err := p.List(ctx, resolved.Path)
			if err != nil {
				return skret.NewError(skret.ExitProviderError, "run: list secrets failed", err)
			}
			if len(secrets) == 0 {
				cmd.PrintErrln("No secrets found to inject. Use 'skret set' to add a secret.")
			}

			if err := validateRequired(secrets, resolved.Required, resolved.Path); err != nil {
				return err
			}

			if err := skexec.DetectEnvNameCollisions(secrets, resolved.Path, resolved.Exclude); err != nil {
				return skret.NewError(skret.ExitConfigError, "run: "+err.Error(), nil)
			}

			if !noResolve {
				if err := resolveInPlace(secrets, resolved.Path); err != nil {
					return err
				}
			}

			env := skexec.BuildEnv(secrets, os.Environ(), resolved.Path, resolved.Exclude)

			if watch {
				return runWatch(cmd, p, resolved, args, secrets, env, watchInterval, noResolve)
			}
			if redactOutput {
				return execRedacted(cmd, args, env, secrets, resolved.Path, redactMinLength)
			}
			return execCommand(args, env)
		},
	}

	cmd.Flags().BoolVar(&watch, "watch", false, "restart the command when secrets change")
	cmd.Flags().DurationVar(&watchInterval, "watch-interval", 15*time.Second, "how often to check for secret changes")
	cmd.Flags().BoolVar(&noResolve, "no-resolve", false, "inject raw stored values without resolving ${KEY} references")
	cmd.Flags().BoolVar(&redactOutput, "redact", false, "mask secret values in the command's stdout and stderr (the command no longer sees a TTY)")
	cmd.Flags().IntVar(&redactMinLength, "redact-min-length", logging.MinRedactedValueLen, "with --redact, leave values shorter than this many bytes unmasked")
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func validateRequired(secrets []*provider.Secret, required []string, path string) error {
	if len(required) == 0 {
		return nil
	}

	secretKeys := make(map[string]bool)
	for _, s := range secrets {
		name := KeyToEnvName(s.Key, path)
		secretKeys[name] = true
	}

	for _, r := range required {
		if !secretKeys[r] && os.Getenv(r) == "" {
			return skret.NewError(skret.ExitValidationError, fmt.Sprintf("run: required secret %q not found", r), nil)
		}
	}

	return nil
}

func execCommand(args []string, env []string) error {
	binary, err := osexec.LookPath(args[0])
	if err != nil {
		return skret.NewError(skret.ExitExecError, fmt.Sprintf("run: command not found: %s", args[0]), err)
	}
	err = skexec.Run(binary, args, env)
	if err != nil {
		// On Windows the child ran as a subprocess: forward its exit code
		// verbatim so `skret run --` matches the Unix exec() behavior (and the
		// documented contract) instead of collapsing every failure to 125.
		// *osexec.ExitError implements ExitCode() int, which skret.ExitCode
		// honors. Non-ExitError failures (spawn errors) stay 125.
		var exitErr *osexec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr
		}
		return skret.NewError(skret.ExitExecError, "runtime error", err)
	}
	return nil
}
