package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/n24q02m/skret/internal/logging"
	"github.com/n24q02m/skret/internal/version"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

// GlobalOpts holds CLI flags shared by all subcommands.
// Passed explicitly to avoid global mutable state.
type GlobalOpts struct {
	Env      string
	Provider string
	Path     string
	Region   string
	Profile  string
	File     string
	Config   string
	LogLevel string
}

// NewRootCmd creates the root Cobra command (exported for testing).
func NewRootCmd() *cobra.Command {
	opts := &GlobalOpts{}

	cmd := &cobra.Command{
		Use:   "skret",
		Short: "Cloud-provider secret manager CLI wrapper",
		Long: fmt.Sprintf("skret wraps cloud-provider secret managers (currently %s)\n"+
			"with Doppler/Infisical-grade developer experience.", formattedProviderList()),
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			// Precedence: --log-level flag > SKRET_LOG env > "info" default.
			level := opts.LogLevel
			if level == "" {
				level = os.Getenv("SKRET_LOG")
			}
			if level == "" {
				level = "info"
			}
			logging.Setup(level, os.Getenv("SKRET_LOG_FORMAT"))
		},
	}

	f := cmd.PersistentFlags()
	f.StringVarP(&opts.Env, "env", "e", "", "target environment (overrides default_env in .skret.yaml)")
	f.StringVar(&opts.Provider, "provider", "", "override provider (aws, local)")
	f.StringVar(&opts.Path, "path", "", "override secret path prefix")
	f.StringVar(&opts.Region, "region", "", "override cloud region")
	f.StringVar(&opts.Profile, "profile", "", "override cloud profile")
	f.StringVar(&opts.File, "file", "", "override local provider file path")
	f.StringVar(&opts.Config, "config", "", "path to a .skret.yaml config file (bypasses directory discovery)")
	f.StringVar(&opts.LogLevel, "log-level", "", "log level (debug, info, warn, error) [env: SKRET_LOG, default: info]")

	// Register subcommands — pass opts explicitly
	cmd.AddCommand(newInitCmd())
	cmd.AddCommand(newSetupCmd())
	cmd.AddCommand(newGetCmd(opts))
	cmd.AddCommand(newListCmd(opts))
	cmd.AddCommand(newEnvCmd(opts))
	cmd.AddCommand(newSetCmd(opts))
	cmd.AddCommand(newDeleteCmd(opts))
	cmd.AddCommand(newHistoryCmd(opts))
	cmd.AddCommand(newRollbackCmd(opts))
	cmd.AddCommand(newRunCmd(opts))
	cmd.AddCommand(newImportCmd(opts))
	cmd.AddCommand(newSyncCmd(opts))
	cmd.AddCommand(newDiffCmd(opts))
	cmd.AddCommand(newTemplateCmd(opts))
	cmd.AddCommand(newScanCmd(opts))
	cmd.AddCommand(newBrowseCmd(opts))
	cmd.AddCommand(newBootstrapCmd(opts))
	cmd.AddCommand(newAuthCmd())
	cmd.AddCommand(newHubCmd(opts))

	// Force cobra's default "completion" command to materialize now (it is
	// normally lazily created during Execute()) so it can be given a real
	// RunE. Without one, cobra treats it as a non-runnable parent and skips
	// its own Args: NoArgs validation entirely -- `skret completion
	// badshell` silently showed help with exit 0 instead of erroring
	// (audit finding M5). ValidCompletionShellArgs replaces cobra's bare
	// NoArgs check with a message that lists the supported shells.
	cmd.InitDefaultCompletionCmd()
	for _, sub := range cmd.Commands() {
		if sub.Name() == "completion" {
			sub.Args = validCompletionShellArgs
			sub.RunE = func(c *cobra.Command, _ []string) error {
				return c.Help()
			}
			// Wrap shell subcommands to capture and redirect their os.Stdout
			for _, shellSub := range sub.Commands() {
				origRun := shellSub.Run
				shellSub.Run = makeCompletionWrapper(origRun, cmd)
			}
			break
		}
	}

	return cmd
}

// makeCompletionWrapper creates a wrapper that redirects os.Stdout writes
// to the root command's configured output. The bash completion script is
// written directly to os.Stdout by Cobra, so we capture it via pipes.
func makeCompletionWrapper(origRun func(*cobra.Command, []string), rootCmd *cobra.Command) func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		oldStdout := os.Stdout
		oldStderr := os.Stderr

		r, w, err := os.Pipe()
		if err != nil {
			origRun(cmd, args)
			return
		}

		os.Stdout = w
		os.Stderr = w

		origRun(cmd, args)

		w.Close()
		os.Stdout = oldStdout
		os.Stderr = oldStderr

		io.Copy(rootCmd.OutOrStdout(), r)
	}
}

// validCompletionShellArgs allows zero args (the completion command then
// shows help via its new RunE) and rejects exactly one unrecognized shell
// name with an actionable, skret-style error. A recognized shell name
// (bash/zsh/fish/powershell) never reaches this validator at all -- cobra
// matches it as a real subcommand first and dispatches straight to that
// subcommand's own RunE.
func validCompletionShellArgs(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return skret.NewError(skret.ExitValidationError,
			fmt.Sprintf("completion: unknown shell %q (available: bash, zsh, fish, powershell)", args[0]), nil)
	}
	return nil
}

// Execute runs the root command.
func Execute() error {
	return NewRootCmd().Execute()
}
