package cli

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/n24q02m/skret/internal/protect"
	"github.com/n24q02m/skret/internal/scanner"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

// protectMaxBytes is the largest file protect reads; a larger one is
// checked by name only.
const protectMaxBytes = 8 << 20

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

Files larger than 8 MiB, binary files (a NUL byte in the first 8 KiB) and
entries that are not regular files (a staged symlink or submodule) are
checked by name only, and protect lists them on stderr. UTF-16 text with a
byte order mark is decoded first, so it is checked like any other text.
--strict also fails (exit 8) on a skipped file, unless it is not a regular
file or its type is binary by design (images, audio, video, fonts, PDF,
compiled code).

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
			var skipped []skippedFile
			scope := "the given paths"
			if len(paths) == 0 {
				scope = "staged files"
				findings, skipped, err = protectStaged(checker)
			} else {
				findings, skipped, err = protectPaths(checker, paths)
			}
			if err != nil {
				return err
			}
			protect.Sort(findings)
			warnSkipped(cmd, skipped)
			unchecked := 0
			if strict {
				unchecked = countUnchecked(skipped)
			}

			if len(findings) == 0 && unchecked == 0 {
				cmd.PrintErrln("No plaintext secrets found.")
			}
			if len(findings) > 0 || format == "json" {
				if format == "json" {
					err = protect.RenderJSON(cmd.OutOrStdout(), findings)
				} else {
					err = protect.RenderTable(cmd.OutOrStdout(), findings)
				}
				if err != nil {
					return err
				}
			}
			if len(findings) == 0 {
				if unchecked == 0 {
					return nil
				}
				return skret.WithRemediation(
					skret.NewError(skret.ExitValidationError,
						fmt.Sprintf("protect: --strict: %d skipped file(s) could not be checked for plaintext secrets", unchecked), nil),
					"check the files listed above by hand, then skip them with --allow, or run without --strict",
				)
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
	cmd.Flags().BoolVar(&strict, "strict", false, "also apply generic heuristics (key=value assignments, long base64-like runs) and fail on skipped files that may hold text")
	cmd.Flags().StringArrayVar(&allow, "allow", nil, "skip paths matching this pattern (repeatable): \"*.pem\" matches names, \"testdata/\" a directory, \"docs/*.md\" a path")
	return cmd
}

// skippedFile is a file protect checked by name only, because its content
// was not read.
type skippedFile struct {
	path   string
	reason scanner.SkipReason
}

// protectStaged checks the staged (index) content of the pending commit.
func protectStaged(checker *protect.Checker) ([]protect.Finding, []skippedFile, error) {
	blobs, err := scanner.StagedBlobs(".", protectMaxBytes)
	if err != nil {
		return nil, nil, skret.WithRemediation(
			skret.NewError(skret.ExitGenericError, "protect: reading staged files failed", err),
			"run inside a git repository, or pass the paths to check",
		)
	}
	var findings []protect.Finding
	var skipped []skippedFile
	for _, b := range blobs {
		findings = append(findings, checker.Check(b.Path, b.Content)...)
		if b.Skipped != "" && !checker.Allowed(b.Path) {
			skipped = append(skipped, skippedFile{b.Path, b.Skipped})
		}
	}
	return findings, skipped, nil
}

// protectPaths checks the named files, expanding directories.
func protectPaths(checker *protect.Checker, paths []string) ([]protect.Finding, []skippedFile, error) {
	var findings []protect.Finding
	var skipped []skippedFile
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, nil, skret.NewError(skret.ExitValidationError, fmt.Sprintf("protect: path %q", p), err)
		}
		files := []string{p}
		if info.IsDir() {
			if files, err = scanner.CandidateFiles(p); err != nil {
				return nil, nil, skret.NewError(skret.ExitGenericError, fmt.Sprintf("protect: listing %q failed", p), err)
			}
		}
		for _, f := range files {
			content, reason, err := scanner.LoadText(f, protectMaxBytes)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, nil, skret.NewError(skret.ExitGenericError, fmt.Sprintf("protect: reading %q failed", f), err)
			}
			findings = append(findings, checker.Check(f, content)...)
			if reason != "" && !checker.Allowed(f) {
				skipped = append(skipped, skippedFile{f, reason})
			}
		}
	}
	return findings, skipped, nil
}

// warnSkipped lists on stderr the files whose content was not read, so a
// clean result never hides what was not checked.
func warnSkipped(cmd *cobra.Command, skipped []skippedFile) {
	if len(skipped) == 0 {
		return
	}
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].path < skipped[j].path })
	cmd.PrintErrf("skret: protect: %d file(s) checked by name only, their content was not read:\n", len(skipped))
	for _, s := range skipped {
		cmd.PrintErrf("  %s: %s\n", s.path, describeSkip(s.reason))
	}
}

func describeSkip(reason scanner.SkipReason) string {
	switch reason {
	case scanner.SkipOversize:
		return fmt.Sprintf("larger than %d MiB", protectMaxBytes>>20)
	case scanner.SkipBinary:
		return "binary (a NUL byte in the first 8 KiB)"
	default:
		return "not a regular file"
	}
}

// countUnchecked counts the skipped files --strict fails on: content that
// could hold text but was not read. A file type that is binary by design,
// and a symlink or submodule (no file content of its own), are not counted.
func countUnchecked(skipped []skippedFile) int {
	n := 0
	for _, s := range skipped {
		if s.reason != scanner.SkipNotRegular && !protect.KnownBinary(s.path) {
			n++
		}
	}
	return n
}
