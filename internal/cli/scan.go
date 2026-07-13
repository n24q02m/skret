package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/n24q02m/skret/internal/scanner"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

func newScanCmd(opts *GlobalOpts) *cobra.Command {
	var (
		format    string
		staged    bool
		minLength int
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan tracked files for any of your managed secret values (leak guard)",
		Long: `Scan tracked files for any of your managed secret values (leak guard).

Matches values literally (not as patterns), so a value containing regex
metacharacters is still found. Exits 10 when a leak is found — wire it into CI
or a pre-commit hook. Use --staged to scan only staged files.`,
		Example: `  skret scan
  skret scan --staged
  skret scan --min-length=8`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolved, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer p.Close()
			warnIfPathMangled(cmd, resolved)

			secrets, err := p.List(context.Background(), resolved.Path)
			if err != nil {
				return skret.NewError(skret.ExitProviderError, "scan: list secrets failed", err)
			}
			if len(secrets) == 0 {
				cmd.PrintErrln("No secrets found to scan. Use 'skret set' to add a secret.")
				return nil
			}

			targets := make([]scanner.Target, 0, len(secrets))
			for _, s := range secrets {
				targets = append(targets, scanner.Target{Key: KeyToEnvName(s.Key, resolved.Path), Value: s.Value})
			}

			dir, err := os.Getwd()
			if err != nil {
				return skret.NewError(skret.ExitGenericError, "scan: getwd failed", err)
			}
			var files []string
			if staged {
				files, err = scanner.StagedFiles(dir)
			} else {
				files, err = scanner.TrackedFiles(dir)
			}
			if err != nil {
				return skret.NewError(skret.ExitGenericError, "scan: list files failed", err)
			}

			findings, err := scanner.Scan(targets, files, scanner.Opts{MinLength: minLength})
			if err != nil {
				return skret.NewError(skret.ExitGenericError, "scan failed", err)
			}

			if len(findings) == 0 {
				cmd.PrintErrln("No leaks found.")
				if format != "json" {
					return nil
				}
			}

			if format == "json" {
				if err := scanner.RenderJSON(cmd.OutOrStdout(), findings); err != nil {
					return err
				}
			} else if err := scanner.RenderTable(cmd.OutOrStdout(), findings); err != nil {
				return err
			}
			if len(findings) > 0 {
				return skret.NewError(skret.ExitLeakFound,
					fmt.Sprintf("scan: %d managed secret value(s) found in tracked files", len(findings)), nil)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "table", "output format (table, json)")
	cmd.Flags().BoolVar(&staged, "staged", false, "scan only staged files (for pre-commit hooks)")
	cmd.Flags().IntVar(&minLength, "min-length", 5, "ignore managed values shorter than this")
	return cmd
}
