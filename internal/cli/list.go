package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

func newListCmd(opts *GlobalOpts) *cobra.Command {
	var (
		format    string
		values    bool
		recursive bool
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secrets under the current environment path",
		Long: "Lists secret key names under the configured environment path. Secrets are listed without " +
			"decryption. Use --values to include the secret values and their version numbers in the output.",
		Example: "  skret list\n  skret list --values",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolved, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer p.Close()

			// Path comes from the resolved config (root persistent --path /
			// SKRET_PATH / .skret.yaml). A local --path here would shadow the
			// root persistent flag and break configless --path usage.
			listPath := resolved.Path

			ctx := context.Background()
			if !values {
				names, err := p.ListNames(ctx, listPath)
				if err != nil {
					return skret.NewError(skret.ExitProviderError, "list secrets failed", err)
				}
				names = filterNames(names, listPath, recursive)
				return printNames(cmd, names, format)
			}

			secrets, err := p.List(ctx, listPath)
			if err != nil {
				return skret.NewError(skret.ExitProviderError, "list secrets failed", err)
			}

			secrets = filterSecrets(secrets, listPath, recursive)
			return printSecrets(cmd, secrets, format, values)
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "output format (table, json)")
	cmd.Flags().BoolVar(&values, "values", false, "include secret values in output")
	cmd.Flags().BoolVar(&recursive, "recursive", true, "list secrets recursively")

	return cmd
}

func filterSecrets(secrets []*provider.Secret, listPath string, recursive bool) []*provider.Secret {
	if recursive || listPath == "" {
		return secrets
	}

	filtered := make([]*provider.Secret, 0, len(secrets))
	level := strings.Count(listPath, "/")
	if !strings.HasSuffix(listPath, "/") {
		level++
	}
	for _, s := range secrets {
		sLevel := strings.Count(s.Key, "/")
		if sLevel == level {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// filterNames mirrors filterSecrets for bare key names.
func filterNames(names []string, listPath string, recursive bool) []string {
	if recursive || listPath == "" {
		return names
	}
	level := strings.Count(listPath, "/")
	if !strings.HasSuffix(listPath, "/") {
		level++
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if strings.Count(n, "/") == level {
			out = append(out, n)
		}
	}
	return out
}

// printNames prints key names only (no VERSION/VALUE), table or json.
func printNames(cmd *cobra.Command, names []string, format string) error {
	if len(names) == 0 {
		cmd.PrintErrln("No secrets found. Use 'skret set' to add a secret.")
		if format != "json" {
			return nil
		}
	}
	switch format {
	case "json":
		items := make([]map[string]any, 0, len(names))
		for _, n := range names {
			items = append(items, map[string]any{"key": n})
		}
		data, err := json.MarshalIndent(items, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal secrets: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
	default:
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "KEY")
		for _, n := range names {
			fmt.Fprintln(w, n)
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("flush failed: %w", err)
		}
	}
	return nil
}

func printSecrets(cmd *cobra.Command, secrets []*provider.Secret, format string, values bool) error {
	if len(secrets) == 0 {
		cmd.PrintErrln("No secrets found. Use 'skret set' to add a secret.")
		if format != "json" {
			return nil
		}
	}

	switch format {
	case "json":
		items := make([]map[string]any, 0, len(secrets))
		for _, s := range secrets {
			item := map[string]any{"key": s.Key}
			if values {
				item["value"] = s.Value
			}
			items = append(items, item)
		}
		data, err := json.MarshalIndent(items, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal secrets: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
	default:
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		if values {
			fmt.Fprintln(w, "KEY\tVERSION\tVALUE")
			for _, s := range secrets {
				fmt.Fprintf(w, "%s\t%d\t%s\n", s.Key, s.Version, s.Value)
			}
		} else {
			fmt.Fprintln(w, "KEY\tVERSION")
			for _, s := range secrets {
				fmt.Fprintf(w, "%s\t%d\n", s.Key, s.Version)
			}
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("flush failed: %w", err)
		}
	}
	return nil
}
