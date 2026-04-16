package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

func newGetCmd(opts *GlobalOpts) *cobra.Command {
	var (
		outputJSON   bool
		withMetadata bool
		plain        bool
	)

	cmd := &cobra.Command{
		Use:   "get <KEY>",
		Short: "Get a single secret value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer p.Close()

			ctx := context.Background()
			secret, err := p.Get(ctx, args[0])
			if err != nil {
				return skret.NewError(skret.ExitNotFoundError, fmt.Sprintf("get %q", args[0]), err)
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
				data, err := json.MarshalIndent(out, "", "  ")
				if err != nil {
					return skret.NewError(skret.ExitGenericError, "get: json marshal failed", err)
				}
				cmd.Println(string(data))
			} else if plain {
				cmd.Print(secret.Value)
			} else {
				cmd.Println(secret.Value)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&withMetadata, "with-metadata", false, "include metadata in output")
	cmd.Flags().BoolVar(&plain, "plain", false, "print value without trailing newline")

	return cmd
}
