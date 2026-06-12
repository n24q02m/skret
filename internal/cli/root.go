package cli

import (
	"fmt"
	"os"

	"github.com/n24q02m/skret/internal/logging"
	"github.com/n24q02m/skret/internal/version"
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
	cmd.AddCommand(newAuthCmd())

	return cmd
}

// Execute runs the root command.
func Execute() error {
	return NewRootCmd().Execute()
}
