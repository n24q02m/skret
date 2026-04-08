package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	var (
		format string
		values bool
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secrets under the current environment path",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolved, p, err := loadProvider()
			if err != nil {
				return err
			}
			defer p.Close()

			ctx := context.Background()
			secrets, err := p.List(ctx, resolved.Path)
			if err != nil {
				return fmt.Errorf("list: %w", err)
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
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "output format (table, json)")
	cmd.Flags().BoolVar(&values, "values", false, "include secret values in output")

	return cmd
}
