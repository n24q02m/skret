package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/n24q02m/skret/internal/differ"
	"github.com/n24q02m/skret/pkg/skret"
)

type diffOptions struct {
	opts       *GlobalOpts
	format     string
	exitCode   bool
	showHash   bool
	dotenv     string
	to         string
	githubRepo string
}

func newDiffCmd(opts *GlobalOpts) *cobra.Command {
	o := &diffOptions{opts: opts}
	cmd := &cobra.Command{
		Use:   "diff <A> [B]",
		Short: "Compare two secret sets (env vs env, env vs dotenv, env vs github)",
		Long: `Compare two secret sets and report which keys differ, without printing
values.

Compares env vs env, env vs a dotenv file, or env vs a GitHub repo's secret
names. Use --show-hash to compare via sha256[:8] and --exit-code to return
non-zero when they differ (useful as a pre-deploy gate).`,
		Example: `  skret diff staging prod
  skret diff staging prod --show-hash
  skret diff prod --to=github --github-repo=owner/repo`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.run(cmd, args)
		},
	}
	cmd.Flags().StringVar(&o.format, "format", "table", "output format (table, json)")
	cmd.Flags().BoolVar(&o.exitCode, "exit-code", false, "exit non-zero when drift is found")
	cmd.Flags().BoolVar(&o.showHash, "show-hash", false, "show sha256[:8] per side for changed keys")
	cmd.Flags().StringVar(&o.dotenv, "dotenv", "", "compare against a dotenv file")
	cmd.Flags().StringVar(&o.to, "to", "", "compare against a target (github)")
	cmd.Flags().StringVar(&o.githubRepo, "github-repo", "", "owner/repo for --to=github")
	return cmd
}

func (o *diffOptions) run(cmd *cobra.Command, args []string) error {
	if len(args) == 2 && o.opts.File != "" {
		return skret.NewError(skret.ExitValidationError, "--file cannot be combined with two environments (it would apply to both sides)", nil)
	}
	a, err := o.buildEnvSource(cmd, args[0])
	if err != nil {
		return err
	}
	b, err := o.buildSecondSide(cmd, args)
	if err != nil {
		return err
	}

	res, err := differ.Diff(cmd.Context(), a, b, differ.Opts{Hashes: o.showHash})
	if err != nil {
		return skret.NewError(skret.ExitProviderError, "diff failed", err)
	}

	switch o.format {
	case "json":
		fmt.Fprintln(cmd.OutOrStdout(), differ.RenderJSON(res))
	case "table":
		fmt.Fprint(cmd.OutOrStdout(), differ.RenderTable(res, differ.TableOpts{ShowHash: o.showHash}))
	default:
		return skret.NewError(skret.ExitValidationError, fmt.Sprintf("unknown --format %q (table, json)", o.format), nil)
	}

	if o.exitCode && res.HasDrift() {
		return skret.NewError(skret.ExitDrift, "drift detected", nil)
	}
	return nil
}

func (o *diffOptions) buildSecondSide(cmd *cobra.Command, args []string) (differ.Source, error) {
	switch {
	case o.dotenv != "" && o.to != "":
		return nil, skret.NewError(skret.ExitValidationError, "use only one of --dotenv or --to", nil)
	case o.dotenv != "":
		if len(args) != 1 {
			return nil, skret.NewError(skret.ExitValidationError, "--dotenv takes exactly one positional (the env)", nil)
		}
		return differ.NewDotenvSource(o.dotenv), nil
	case o.to == "github":
		if len(args) != 1 {
			return nil, skret.NewError(skret.ExitValidationError, "--to=github takes exactly one positional (the env)", nil)
		}
		owner, repo, err := splitOwnerRepo(o.githubRepo)
		if err != nil {
			return nil, err
		}
		token, err := requireGitHubToken()
		if err != nil {
			return nil, err
		}
		return differ.NewGitHubSource(owner, repo, token, ""), nil
	case o.to != "":
		return nil, skret.NewError(skret.ExitValidationError, fmt.Sprintf("unknown --to %q (github)", o.to), nil)
	case len(args) == 2:
		return o.buildEnvSource(cmd, args[1])
	default:
		return nil, skret.NewError(skret.ExitValidationError, "diff needs a second env, --dotenv, or --to=github", nil)
	}
}

func (o *diffOptions) buildEnvSource(cmd *cobra.Command, target string) (differ.Source, error) {
	sideOpts := *o.opts
	isPath := target != "" && target[0] == '/'
	if isPath {
		sideOpts.Path = target
	} else {
		sideOpts.Env = target
	}
	resolved, p, err := loadProvider(&sideOpts)
	if err != nil {
		return nil, err
	}
	warnIfPathMangled(cmd, resolved)
	label := "env:" + resolved.EnvName
	if isPath {
		label = "path:" + resolved.Path
	}
	return differ.NewEnvSource(label, p, resolved.Path), nil
}

func splitOwnerRepo(s string) (owner, repo string, err error) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", skret.NewError(skret.ExitValidationError, "--github-repo must be owner/repo", nil)
	}
	return parts[0], parts[1], nil
}

func requireGitHubToken() (string, error) {
	tok := os.Getenv("GITHUB_TOKEN")
	if tok == "" {
		return "", skret.NewError(skret.ExitValidationError, "GITHUB_TOKEN is required for --to=github", nil)
	}
	return tok, nil
}
