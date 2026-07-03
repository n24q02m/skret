package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/n24q02m/skret/internal/provider"
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
		Long: `Print a single secret value to stdout.

By default a trailing newline is added for readability; use --plain for the
exact bytes (e.g. when capturing in a script) and --json for a parseable
object. To read ALL secrets use 'skret env'; to inject them into a command use
'skret run'.`,
		Example: `  skret get DATABASE_URL
  skret get DATABASE_URL --plain
  skret get DATABASE_URL --json`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: secretKeyCompletion(opts),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			secret, err := p.Get(ctx, key)
			if err != nil {
				return skret.NewError(skret.ExitNotFoundError, fmt.Sprintf("get %q", key), err)
			}

			return printSecret(cmd, secret, outputJSON, withMetadata, plain)
		},
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&withMetadata, "with-metadata", false, "include metadata in output")
	cmd.Flags().BoolVar(&plain, "plain", false, "print value without trailing newline")

	return cmd
}

func printSecret(cmd *cobra.Command, secret *provider.Secret, outputJSON, withMetadata, plain bool) error {
	stdout := cmd.OutOrStdout()
	switch {
	case outputJSON || withMetadata:
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
		fmt.Fprintln(stdout, string(data))
	case plain:
		fmt.Fprint(stdout, secret.Value)
	default:
		fmt.Fprintln(stdout, secret.Value)
	}
	return nil
}
