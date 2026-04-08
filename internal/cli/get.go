package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func newGetCmd() *cobra.Command {
	var (
		outputJSON   bool
		withMetadata bool
	)

	cmd := &cobra.Command{
		Use:   "get <KEY>",
		Short: "Get a single secret value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, p, err := loadProvider()
			if err != nil {
				return err
			}
			defer p.Close()

			ctx := context.Background()
			secret, err := p.Get(ctx, args[0])
			if err != nil {
				return fmt.Errorf("get %q: %w", args[0], err)
			}

			if outputJSON || withMetadata {
				out := map[string]any{
					"key":   secret.Key,
					"value": secret.Value,
				}
				if withMetadata {
					out["version"] = secret.Version
					out["meta"] = secret.Meta
				}
				data, _ := json.MarshalIndent(out, "", "  ")
				cmd.Println(string(data))
			} else {
				cmd.Println(secret.Value)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&withMetadata, "with-metadata", false, "include metadata in output")

	return cmd
}
