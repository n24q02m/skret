package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

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
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer p.Close()

			key := args[0]

			if !confirm && !force {
				cmd.Printf("Delete secret %q? [y/N] ", key)
				reader := bufio.NewReader(os.Stdin)
				answer, _ := reader.ReadString('\n')
				if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
					cmd.Println("Cancelled.")
					return nil
				}
			}

			ctx := context.Background()
			if err := p.Delete(ctx, key); err != nil {
				return skret.NewError(skret.ExitProviderError, fmt.Sprintf("delete %q failed", key), err)
			}

			cmd.Printf("Deleted %s\n", key)
			return nil
		},
	}

	cmd.Flags().BoolVar(&confirm, "confirm", false, "skip confirmation prompt")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "skip confirmation prompt (alias for --confirm)")

	return cmd
}
