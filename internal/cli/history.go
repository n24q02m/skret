package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

// historyEntry is the --format json shape for one history row. It is a
// dedicated type rather than marshaling []*provider.Secret directly for two
// reasons: provider.Secret's untagged field names (Key, Value, ...) don't
// match this codebase's lowercase JSON convention (list.go, get.go, diff.go),
// and Value must go through the same mask-by-default/--verbose-to-reveal
// policy the table already applies -- marshaling the raw slice would leak
// full values in JSON even when the caller omitted --verbose.
type historyEntry struct {
	Version   int64  `json:"version"`
	Value     string `json:"value"`
	UpdatedAt string `json:"updated_at,omitempty"`
	Author    string `json:"author,omitempty"`
}

func newHistoryCmd(opts *GlobalOpts) *cobra.Command {
	var (
		verbose bool
		format  string
	)

	cmd := &cobra.Command{
		Use:   "history <KEY>",
		Short: "View the version history of a secret",
		Long: "Shows the version history of a secret, including version number, timestamp, and author. " +
			"Values are masked by default for security; use --verbose to display full unmasked values. " +
			"This command is experimental — set SKRET_EXPERIMENTAL=1 to enable it.",
		Example:           "  SKRET_EXPERIMENTAL=1 skret history DATABASE_URL",
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
			warnIfPathMangled(cmd, resolved)

			ctx := context.Background()
			key, mangled := resolveKeyArg(resolved.Path, args[0])
			if mangled {
				cmd.PrintErrf("warning: key looked shell-mangled; using %q (omit the leading slash, or set MSYS_NO_PATHCONV=1)\n", key)
			}

			history, err := p.GetHistory(ctx, key)
			if err != nil {
				return skret.NewError(skret.ExitProviderError, fmt.Sprintf("failed to get history for %q", key), err)
			}

			return renderHistory(cmd, history, key, verbose, format)
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "display full unmasked secret values")
	cmd.Flags().StringVar(&format, "format", "table", "output format (table, json)")

	return cmd
}

// renderHistory formats and prints the history table or, for --format json,
// the same rows as a JSON array (see historyEntry).
func renderHistory(cmd *cobra.Command, history []*provider.Secret, key string, verbose bool, format string) error {
	if len(history) == 0 {
		cmd.PrintErrf("No history found for %q. Use 'skret set' to create a version.\n", key)
		if format != "json" {
			return nil
		}
	}

	if format == "json" {
		return renderHistoryJSON(cmd, history, verbose)
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

// renderHistoryJSON writes history as a JSON array, applying the same
// mask-by-default/--verbose policy as the table.
func renderHistoryJSON(cmd *cobra.Command, history []*provider.Secret, verbose bool) error {
	entries := make([]historyEntry, 0, len(history))
	for _, s := range history {
		val := s.Value
		if !verbose {
			val = maskValue(val)
		}
		entry := historyEntry{Version: s.Version, Value: val, Author: s.Meta.CreatedBy}
		if !s.Meta.UpdatedAt.IsZero() {
			entry.UpdatedAt = s.Meta.UpdatedAt.Format(time.RFC3339)
		}
		entries = append(entries, entry)
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return skret.NewError(skret.ExitGenericError, "history: encode result", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
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
