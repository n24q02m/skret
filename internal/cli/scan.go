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
		history   bool
		since     string
		maxCount  int
		minLength int
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan tracked files for any of your managed secret values (leak guard)",
		Long: `Scan tracked files for any of your managed secret values (leak guard).

Matches values literally (not as patterns), so a value containing regex
metacharacters is still found. Exits 10 when a leak is found — wire it into CI
or a pre-commit hook. Use --staged to scan only staged files, or --history to
scan committed blobs across git history (bounded walk; each unique blob is
reported at the commit that introduced it).`,
		Example: `  skret scan
  skret scan --staged
  skret scan --min-length=8
  skret scan --history
  skret scan --history --since="2 weeks ago" --max-count=200 --format json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if staged && history {
				return skret.WithRemediation(
					skret.NewError(skret.ExitGenericError, "scan: --staged and --history are mutually exclusive", nil),
					"pick one scope: --staged scans pending commit content, --history scans committed blobs",
				)
			}
			if !history && since != "" {
				return skret.WithRemediation(
					skret.NewError(skret.ExitGenericError, "scan: --since only applies to --history", nil),
					"add --history, or drop --since",
				)
			}
			if !history && cmd.Flags().Changed("max-count") {
				return skret.WithRemediation(
					skret.NewError(skret.ExitGenericError, "scan: --max-count only applies to --history", nil),
					"add --history, or drop --max-count",
				)
			}
			if history && maxCount < 1 {
				return skret.WithRemediation(
					skret.NewError(skret.ExitGenericError, "scan: --max-count must be at least 1", nil),
					"pass a positive commit cap, e.g. --max-count=500 (default 1000)",
				)
			}
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
			// Provide actionable feedback for empty states to improve UX
			if len(secrets) == 0 && !staged {
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
			var findings []scanner.Finding
			switch {
			case history:
				findings, err = scanner.HistoryScan(targets, dir, scanner.HistoryOpts{
					Opts:     scanner.Opts{MinLength: minLength},
					MaxCount: maxCount,
					Since:    since,
				})
				if err != nil {
					return skret.WithRemediation(
						skret.NewError(skret.ExitGenericError, "scan: history scan failed", err),
						"make sure git is installed and the directory is a git repository, or use plain 'skret scan' for the working tree",
					)
				}
			case staged:
				files, listErr := scanner.StagedFiles(dir)
				if listErr != nil {
					return skret.NewError(skret.ExitGenericError, "scan: list files failed", listErr)
				}
				findings, err = scanner.Scan(targets, files, scanner.Opts{MinLength: minLength})
				if err != nil {
					return skret.NewError(skret.ExitGenericError, "scan failed", err)
				}
			default:
				files, listErr := scanner.TrackedFiles(dir)
				if listErr != nil {
					return skret.NewError(skret.ExitGenericError, "scan: list files failed", listErr)
				}
				findings, err = scanner.Scan(targets, files, scanner.Opts{MinLength: minLength})
				if err != nil {
					return skret.NewError(skret.ExitGenericError, "scan failed", err)
				}
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
				scope := "tracked files"
				if staged {
					scope = "staged files"
				}
				if history {
					scope = "git history"
				}
				var leakErr error = skret.NewError(skret.ExitLeakFound,
					fmt.Sprintf("scan: %d managed secret value(s) found in %s", len(findings), scope), nil)
				if history {
					leakErr = skret.WithRemediation(leakErr,
						"rotate the exposed secret value, then purge it from git history (e.g. git filter-repo) before pushing to remotes")
				}
				return leakErr
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "table", "output format (table, json)")
	cmd.Flags().BoolVar(&staged, "staged", false, "scan only staged files (for pre-commit hooks)")
	cmd.Flags().BoolVar(&history, "history", false, "scan committed blobs across git history (bounded walk)")
	cmd.Flags().StringVar(&since, "since", "", "with --history: only scan commits newer than this git date (e.g. \"2 weeks ago\")")
	cmd.Flags().IntVar(&maxCount, "max-count", scanner.DefaultHistoryMaxCount, "with --history: cap the number of commits walked")
	cmd.Flags().IntVar(&minLength, "min-length", 5, "ignore managed values shorter than this")
	return cmd
}
