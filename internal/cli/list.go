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
		path      string
		recursive bool
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secrets under the current environment path",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolved, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer p.Close()

			listPath := resolved.Path
			if path != "" {
				listPath = path
			}

			// Ensure prefix slash
			if listPath != "" && !strings.HasPrefix(listPath, "/") {
				listPath = "/" + listPath
			}

			ctx := context.Background()
			secrets, err := p.List(ctx, listPath)
			if err != nil {
				return skret.NewError(skret.ExitProviderError, "list secrets failed", err)
			}

			secrets = filterSecrets(secrets, listPath, recursive)
			printSecrets(cmd, secrets, format, values)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "output format (table, json)")
	cmd.Flags().BoolVar(&values, "values", false, "include secret values in output")
	cmd.Flags().StringVar(&path, "path", "", "override path prefix to list")
	cmd.Flags().BoolVar(&recursive, "recursive", true, "list secrets recursively")

	return cmd
}

func filterSecrets(secrets []*provider.Secret, listPath string, recursive bool) []*provider.Secret {
	if recursive || listPath == "" {
		return secrets
	}

	var filtered []*provider.Secret
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

func printSecrets(cmd *cobra.Command, secrets []*provider.Secret, format string, values bool) {
	if len(secrets) == 0 {
		switch format {
		case "json":
			cmd.Println("[]")
		case "table", "":
			cmd.Println("No secrets found. Use 'skret set <key> <value>' to add one.")
		}
		return
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
		data, _ := json.MarshalIndent(items, "", "  ")
		cmd.Println(string(data))
	default:
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "KEY\tVERSION")
		for _, s := range secrets {
			fmt.Fprintf(w, "%s\t%d\n", s.Key, s.Version)
		}
		w.Flush()
	}
}
