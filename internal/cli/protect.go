package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/n24q02m/skret/internal/protect"
	"github.com/n24q02m/skret/internal/scanner"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

func newProtectCmd() *cobra.Command {
	var (
		format string
		strict bool
		allow  []string
	)
	cmd := &cobra.Command{
		Use:   "protect [path...]",
		Short: "Block .env files and plaintext credentials from being committed (pre-commit guard)",
		Long: `Block .env files and plaintext credentials from being committed.

With no arguments, checks the files staged for the next commit, reading their
staged content from the git index. With paths, checks those files instead;
a directory covers the files under it that git would let you commit (tracked
and untracked, minus .gitignore), or every file outside a git repository.

Two kinds of finding are reported:
  env-file   a dotenv file (.env, .env.local, prod.env, ...). Templates ending
             in .example, .sample, .template or .dist are allowed; their
             content is still checked.
  <format>   a well-known credential format (GitHub, AWS, Slack, Stripe,
             Google, GitLab, npm and PyPI tokens, private keys, ...).

--strict adds the generic heuristics skret uses to redact its own logs
(key=value assignments, long base64-like runs); expect false positives on
hashes and lockfiles. Skip intentional fixtures with --allow, or put
"skret:allow" on the line.

Unlike 'skret scan', protect needs no .skret.yaml or provider: it looks for
secret shapes, not for your managed values. Output names the file, line and
rule, never the matched text. Exits 10 when anything is found.`,
		Example: `  skret protect
  skret protect .env.production config/
  skret protect --allow 'testdata/' --allow '*.pem.example'
  skret protect --strict --format json`,
		RunE: func(cmd *cobra.Command, paths []string) error {
			if format != "table" && format != "json" {
				return skret.NewError(skret.ExitValidationError,
					fmt.Sprintf("protect: unknown --format %q (use table or json)", format), nil)
			}
			checker, err := protect.New(protect.Options{Strict: strict, Allow: allow})
			if err != nil {
				return skret.NewError(skret.ExitValidationError, "protect: --allow: "+err.Error(), nil)
			}

			var findings []protect.Finding
			scope := "the given paths"
			if len(paths) == 0 {
				scope = "staged files"
				findings, err = protectStaged(checker)
			} else {
				findings, err = protectPaths(checker, paths)
			}
			if err != nil {
				return err
			}
			protect.Sort(findings)

			if len(findings) == 0 {
				cmd.PrintErrln("No plaintext secrets found.")
				if format != "json" {
					return nil
				}
			}
			if format == "json" {
				err = protect.RenderJSON(cmd.OutOrStdout(), findings)
			} else {
				err = protect.RenderTable(cmd.OutOrStdout(), findings)
			}
			if err != nil {
				return err
			}
			if len(findings) == 0 {
				return nil
			}
			return skret.WithRemediation(
				skret.NewError(skret.ExitLeakFound,
					fmt.Sprintf("protect: %d finding(s) in %s", len(findings), scope), nil),
				"remove the secret or unstage the file (git rm --cached <file>) and rotate any credential that was exposed; "+
					"mark intentional fixtures with --allow or a skret:allow comment",
			)
		},
	}
	cmd.Flags().StringVar(&format, "format", "table", "output format (table, json)")
	cmd.Flags().BoolVar(&strict, "strict", false, "also apply generic heuristics (key=value assignments, long base64-like runs)")
	cmd.Flags().StringArrayVar(&allow, "allow", nil, "skip paths matching this pattern (repeatable): \"*.pem\" matches names, \"testdata/\" a directory, \"docs/*.md\" a path")
	return cmd
}

// protectStaged checks the staged (index) content of the pending commit.
func protectStaged(checker *protect.Checker) ([]protect.Finding, error) {
	blobs, err := scanner.StagedBlobs(".", 0)
	if err != nil {
		return nil, skret.WithRemediation(
			skret.NewError(skret.ExitGenericError, "protect: reading staged files failed", err),
			"run inside a git repository, or pass the paths to check",
		)
	}
	var findings []protect.Finding
	for _, b := range blobs {
		findings = append(findings, checker.Check(b.Path, b.Content)...)
	}
	return findings, nil
}

// protectPaths checks the named files, expanding directories.
func protectPaths(checker *protect.Checker, paths []string) ([]protect.Finding, error) {
	var findings []protect.Finding
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, skret.NewError(skret.ExitValidationError, fmt.Sprintf("protect: path %q", p), err)
		}
		files := []string{p}
		if info.IsDir() {
			if files, err = scanner.CandidateFiles(p); err != nil {
				return nil, skret.NewError(skret.ExitGenericError, fmt.Sprintf("protect: listing %q failed", p), err)
			}
		}
		for _, f := range files {
			content, err := scanner.LoadText(f, 0)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, skret.NewError(skret.ExitGenericError, fmt.Sprintf("protect: reading %q failed", f), err)
			}
			findings = append(findings, checker.Check(f, content)...)
		}
	}
	return findings, nil
}
