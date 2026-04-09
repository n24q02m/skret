package cli

import (
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
		Use:           "skret",
		Short:         "Cloud-provider secret manager CLI wrapper",
		Long:          "skret wraps cloud-provider secret managers (AWS SSM, GCP, Azure, OCI, Cloudflare)\nwith Doppler/Infisical-grade developer experience.",
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			logging.Setup(opts.LogLevel, "")
		},
	}

	f := cmd.PersistentFlags()
	f.StringVarP(&opts.Env, "env", "e", "", "target environment (overrides default_env in .skret.yaml)")
	f.StringVar(&opts.Provider, "provider", "", "override provider (aws, local)")
	f.StringVar(&opts.Path, "path", "", "override secret path prefix")
	f.StringVar(&opts.Region, "region", "", "override cloud region")
	f.StringVar(&opts.Profile, "profile", "", "override cloud profile")
	f.StringVar(&opts.File, "file", "", "override local provider file path")
	f.StringVar(&opts.LogLevel, "log-level", "info", "log level (debug, info, warn, error)")

	// Register subcommands — pass opts explicitly
	cmd.AddCommand(newInitCmd())
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

	return cmd
}

// Execute runs the root command.
func Execute() error {
	return NewRootCmd().Execute()
}
