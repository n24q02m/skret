package cli

import (
	"github.com/n24q02m/skret/internal/version"
	"github.com/spf13/cobra"
)

// Global flags shared by all subcommands.
var globalOpts struct {
	env      string
	provider string
	path     string
	region   string
	profile  string
	file     string
	logLevel string
}

// NewRootCmd creates the root Cobra command (exported for testing).
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "skret",
		Short:         "Cloud-provider secret manager CLI wrapper",
		Long:          "skret wraps cloud-provider secret managers (AWS SSM, GCP, Azure, OCI, Cloudflare)\nwith Doppler/Infisical-grade developer experience.",
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.PersistentFlags()
	f.StringVarP(&globalOpts.env, "env", "e", "", "target environment (overrides default_env in .skret.yaml)")
	f.StringVar(&globalOpts.provider, "provider", "", "override provider (aws, local)")
	f.StringVar(&globalOpts.path, "path", "", "override secret path prefix")
	f.StringVar(&globalOpts.region, "region", "", "override cloud region")
	f.StringVar(&globalOpts.profile, "profile", "", "override cloud profile")
	f.StringVar(&globalOpts.file, "file", "", "override local provider file path")
	f.StringVar(&globalOpts.logLevel, "log-level", "info", "log level (debug, info, warn, error)")

	// Register subcommands
	cmd.AddCommand(newInitCmd())
	cmd.AddCommand(newGetCmd())
	cmd.AddCommand(newListCmd())
	cmd.AddCommand(newEnvCmd())
	cmd.AddCommand(newSetCmd())
	cmd.AddCommand(newDeleteCmd())
	cmd.AddCommand(newRunCmd())
	cmd.AddCommand(newImportCmd())
	cmd.AddCommand(newSyncCmd())

	return cmd
}

// Execute runs the root command.
func Execute() error {
	return NewRootCmd().Execute()
}
