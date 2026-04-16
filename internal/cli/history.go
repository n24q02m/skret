package cli

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

func newHistoryCmd(opts *GlobalOpts) *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "history <KEY>",
		Short: "View the version history of a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Getenv("SKRET_EXPERIMENTAL") != "1" {
				return skret.NewError(skret.ExitValidationError, "history is experimental; set SKRET_EXPERIMENTAL=1 to enable", nil)
			}

			_, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer func() { _ = p.Close() }()

			ctx := context.Background()
			key := args[0]

			history, err := p.GetHistory(ctx, key)
			if err != nil {
				return skret.NewError(skret.ExitProviderError, fmt.Sprintf("failed to get history for %q", key), err)
			}

			renderHistory(cmd, history, key, verbose)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "display full unmasked secret values")

	return cmd
}

// renderHistory formats and prints the history table.
func renderHistory(cmd *cobra.Command, history []*provider.Secret, key string, verbose bool) {
	if len(history) == 0 {
		cmd.Printf("No history found for %q\n", key)
		return
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "VERSION\tVALUE\tUPDATED AT\tAUTHOR")

	for _, s := range history {
		val := s.Value
		if !verbose {
			if len(val) > 8 {
				val = val[:4] + "..." + val[len(val)-4:]
			} else {
				val = "***"
			}
		}

		updatedAt := s.Meta.UpdatedAt.Format(time.RFC3339)
		if s.Meta.UpdatedAt.IsZero() {
			updatedAt = "-"
		}

		author := s.Meta.CreatedBy
		if author == "" {
			author = "-"
		}

		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", s.Version, val, updatedAt, author)
	}
	_ = w.Flush()
}
