package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

func newRollbackCmd(opts *GlobalOpts) *cobra.Command {
	var (
		confirm bool
		force   bool
	)

	cmd := &cobra.Command{
		Use:   "rollback <KEY> <VERSION>",
		Short: "Restore a secret to a specific previous version",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Getenv("SKRET_EXPERIMENTAL") != "1" {
				return skret.NewError(skret.ExitValidationError, "rollback is experimental; set SKRET_EXPERIMENTAL=1 to enable", nil)
			}

			_, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer p.Close()

			ctx := context.Background()
			key := args[0]
			versionStr := args[1]

			if !confirm && !force {
				cmd.PrintErrf("Rollback secret %q to version %s? [y/N] ", key, versionStr)
				reader := bufio.NewReader(cmd.InOrStdin())
				answer, _ := reader.ReadString('\n')
				if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
					cmd.PrintErrln("Cancelled.")
					return nil
				}
			}

			version, err := strconv.ParseInt(versionStr, 10, 64)
			if err != nil {
				return skret.NewError(skret.ExitProviderError, "invalid version number", err)
			}

			err = p.Rollback(ctx, key, version)
			if err != nil {
				return skret.NewError(skret.ExitProviderError, fmt.Sprintf("failed to rollback %q to version %d", key, version), err)
			}

			cmd.PrintErrf("Successfully rolled back %q to version %d\n", key, version)
			return nil
		},
	}

	cmd.Flags().BoolVar(&confirm, "confirm", false, "skip confirmation prompt")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "skip confirmation prompt (alias for --confirm)")

	return cmd
}
