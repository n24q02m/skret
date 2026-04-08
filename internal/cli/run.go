package cli

import (
	"context"
	"fmt"
	"os"
	osexec "os/exec"

	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/spf13/cobra"
)

func newRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                "run -- <command> [args...]",
		Short:              "Run a command with secrets injected as environment variables",
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("run: command required after --")
			}

			resolved, p, err := loadProvider()
			if err != nil {
				return err
			}
			defer p.Close()

			ctx := context.Background()
			secrets, err := p.List(ctx, resolved.Path)
			if err != nil {
				return fmt.Errorf("run: list secrets: %w", err)
			}

			// Validate required secrets
			if len(resolved.Required) > 0 {
				secretKeys := make(map[string]bool)
				for _, s := range secrets {
					name := secretKeyToEnvVar(s.Key, resolved.Path)
					secretKeys[name] = true
				}
				for _, r := range resolved.Required {
					if !secretKeys[r] && os.Getenv(r) == "" {
						return fmt.Errorf("run: required secret %q not found", r)
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

func execCommand(args []string, env []string) error {
	binary, err := osexec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("run: command not found: %s", args[0])
	}

	// On Windows: use os/exec.Command
	c := osexec.Command(binary, args[1:]...)
	c.Env = env
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
