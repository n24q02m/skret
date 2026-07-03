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
		Long: "Shows the version history of a secret, including version number, timestamp, and author. " +
			"Values are masked by default for security; use --verbose to display full unmasked values.",
		Example:           "  skret history DATABASE_URL",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: secretKeyCompletion(opts),
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Getenv("SKRET_EXPERIMENTAL") != "1" {
				return skret.NewError(skret.ExitValidationError, "history is experimental; set SKRET_EXPERIMENTAL=1 to enable", nil)
			}

			resolved, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer p.Close()

			ctx := context.Background()
			key, mangled := resolveKeyArg(resolved.Path, args[0])
			if mangled {
				cmd.PrintErrf("warning: key looked shell-mangled; using %q (omit the leading slash, or set MSYS_NO_PATHCONV=1)\n", key)
			}

			history, err := p.GetHistory(ctx, key)
			if err != nil {
				return skret.NewError(skret.ExitProviderError, fmt.Sprintf("failed to get history for %q", key), err)
			}

			return renderHistory(cmd, history, key, verbose)
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "display full unmasked secret values")

	return cmd
}

// renderHistory formats and prints the history table.
func renderHistory(cmd *cobra.Command, history []*provider.Secret, key string, verbose bool) error {
	if len(history) == 0 {
		cmd.PrintErrf("No history found for %q. Use 'skret set' to create a version.\n", key)
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VERSION\tVALUE\tUPDATED AT\tAUTHOR")

	for _, s := range history {
		val := s.Value
		if !verbose {
			val = maskValue(val)
		}

		updatedAt := s.Meta.UpdatedAt.Format(time.RFC3339)
		if s.Meta.UpdatedAt.IsZero() {
			updatedAt = "-"
		}

		author := s.Meta.CreatedBy
		if author == "" {
			author = "-"
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", s.Version, val, updatedAt, author)
	}
	return w.Flush()
}

// maskValue shows the first and last 4 runes of a value with an ellipsis between,
// or "***" if it is 8 runes or shorter. It slices on rune boundaries so a value
// with multi-byte runes is never split into invalid UTF-8.
func maskValue(val string) string {
	r := []rune(val)
	if len(r) > 8 {
		return string(r[:4]) + "..." + string(r[len(r)-4:])
	}
	return "***"
}
