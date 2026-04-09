package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

func newSetCmd(opts *GlobalOpts) *cobra.Command {
	var (
		fromStdin   bool
		fromFile    string
		description string
		tags        []string
	)

	cmd := &cobra.Command{
		Use:   "set <KEY> [VALUE]",
		Short: "Create or update a secret",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer p.Close()

			key := args[0]
			var value string

			switch {
			case len(args) == 2:
				value = args[1]
			case fromStdin:
				scanner := bufio.NewScanner(os.Stdin)
				if scanner.Scan() {
					value = scanner.Text()
				}
				if err := scanner.Err(); err != nil {
					return skret.NewError(skret.ExitGenericError, "set: read stdin failed", err)
				}
			case fromFile != "":
				data, err := os.ReadFile(fromFile)
				if err != nil {
					return skret.NewError(skret.ExitGenericError, fmt.Sprintf("set: read file %q", fromFile), err)
				}
				value = strings.TrimRight(string(data), "\n")
			default:
				return skret.NewError(skret.ExitValidationError, "set: value required (provide as argument, --from-stdin, or --from-file)", nil)
			}

			meta := provider.SecretMeta{Description: description}
			if len(tags) > 0 {
				meta.Tags = make(map[string]string, len(tags))
				for _, tag := range tags {
					parts := strings.SplitN(tag, "=", 2)
					if len(parts) == 2 {
						meta.Tags[parts[0]] = parts[1]
					}
				}
			}

			ctx := context.Background()
			if err := p.Set(ctx, key, value, meta); err != nil {
				return skret.NewError(skret.ExitProviderError, fmt.Sprintf("set %q", key), err)
			}

			cmd.Printf("Set %s\n", key)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&fromStdin, "from-stdin", "s", false, "read value from stdin")
	cmd.Flags().StringVarP(&fromFile, "from-file", "f", "", "read value from file")
	cmd.Flags().StringVarP(&description, "description", "d", "", "secret description")
	cmd.Flags().StringArrayVarP(&tags, "tag", "t", nil, "secret tag (key=value, repeatable)")

	return cmd
}
