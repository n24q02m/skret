package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

func newDeleteCmd(opts *GlobalOpts) *cobra.Command {
	var (
		confirm bool
		force   bool
	)

	cmd := &cobra.Command{
		Use:   "delete <KEY>",
		Short: "Delete a secret",
		Long: "Deletes a secret by its key. Requires confirmation unless --confirm or --force is passed. " +
			"The secret is permanently removed from the provider.",
		Example:           "  skret delete OLD_TOKEN",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: secretKeyCompletion(opts),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer p.Close()
			warnIfPathMangled(cmd, resolved)

			key, mangled := resolveKeyArg(resolved.Path, args[0])
			if mangled {
				cmd.PrintErrf("warning: key looked shell-mangled; using %q (omit the leading slash, or set MSYS_NO_PATHCONV=1)\n", key)
			}

			if !confirm && !force {
				cmd.PrintErrf("Delete secret %q? [y/N] ", key)
				reader := bufio.NewReader(cmd.InOrStdin())
				answer, _ := reader.ReadString('\n')
				if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
					cmd.PrintErrln("Cancelled.")
					return nil
				}
			}

			ctx := context.Background()
			if err := p.Delete(ctx, key); err != nil {
				if errors.Is(err, provider.ErrNotFound) {
					return skret.NewError(skret.ExitNotFoundError, fmt.Sprintf("Nothing to delete: %q not found. Use 'skret history %s' to check if it existed before.", key, key), err)
				}
				return skret.NewError(skret.ExitProviderError, fmt.Sprintf("delete %q failed", key), err)
			}

			cmd.PrintErrf("Deleted %s\n", key)
			return nil
		},
	}

	cmd.Flags().BoolVar(&confirm, "confirm", false, "skip confirmation prompt")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "skip confirmation prompt (alias for --confirm)")

	return cmd
}
