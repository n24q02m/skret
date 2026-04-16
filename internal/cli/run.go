package cli

import (
	"context"
	"fmt"
	"os"
	osexec "os/exec"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

func newRunCmd(opts *GlobalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:                "run -- <command> [args...]",
		Short:              "Run a command with secrets injected as environment variables",
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

			ctx := context.Background()
			secrets, err := p.List(ctx, resolved.Path)
			if err != nil {
				return skret.NewError(skret.ExitProviderError, "run: list secrets failed", err)
			}

			// Validate required secrets
			if len(resolved.Required) > 0 {
				secretKeys := make(map[string]bool)
				for _, s := range secrets {
					name := KeyToEnvName(s.Key, resolved.Path)
					secretKeys[name] = true
				}
				for _, r := range resolved.Required {
					if !secretKeys[r] && os.Getenv(r) == "" {
						return skret.NewError(skret.ExitValidationError, fmt.Sprintf("run: required secret %q not found", r), nil)
					}
				}
			}

			env := skexec.BuildEnv(secrets, os.Environ(), resolved.Path, resolved.Exclude)

			return execCommand(args, env)
		},
	}

	cmd.Flags().SetInterspersed(false)
	return cmd
}

var skexecRun = skexec.Run

func execCommand(args []string, env []string) error {
	binary, err := osexec.LookPath(args[0])
	if err != nil {
		return skret.NewError(skret.ExitExecError, fmt.Sprintf("run: command not found: %s", args[0]), err)
	}
	err = skexecRun(binary, args, env)
	if err != nil {
		return skret.NewError(skret.ExitExecError, "runtime error", err)
	}
	return nil
}
