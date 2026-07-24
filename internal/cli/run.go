package cli

import (
	"context"
	"fmt"
	"os"
	osexec "os/exec"
	"time"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

func newRunCmd(opts *GlobalOpts) *cobra.Command {
	var watch bool
	var watchInterval time.Duration
	cmd := &cobra.Command{
		Use:   "run -- <command> [args...]",
		Short: "Run a command with secrets injected as environment variables",
		Long: `Run a command with all secrets injected as environment variables.

Values are injected verbatim, except three bytes that an OS environment cannot
carry: NUL and CR are dropped and LF is replaced with a space (see the
value-fidelity guide). Use --watch to auto-restart the command when a secret
changes.`,
		Example: `  skret run -- make deploy
  skret run -- ./server
  skret run --watch -- make up-prod`,
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return skret.NewError(skret.ExitValidationError, "run: command required after --", nil)
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

			env := skexec.BuildEnv(secrets, os.Environ(), resolved.Path, resolved.Exclude)

			if watch {
				return runWatch(cmd, p, resolved, args, secrets, env, watchInterval)
			}
			return execCommand(args, env)
		},
	}

	cmd.Flags().BoolVar(&watch, "watch", false, "restart the command when secrets change")
	cmd.Flags().DurationVar(&watchInterval, "watch-interval", 15*time.Second, "how often to check for secret changes")
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
		return skret.NewError(skret.ExitExecError, "runtime error", err)
	}
	return nil
}
