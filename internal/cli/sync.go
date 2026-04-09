package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/n24q02m/skret/internal/syncer"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

func newSyncCmd(opts *GlobalOpts) *cobra.Command {
	var (
		to         string
		file       string
		githubRepo string
	)

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync secrets to external targets (dotenv, github)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolved, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer p.Close()

			ctx := context.Background()
			secrets, err := p.List(ctx, resolved.Path)
			if err != nil {
				return skret.NewError(skret.ExitProviderError, "sync: list secrets failed", err)
			}

			var syncers []syncer.Syncer
			switch to {
			case "dotenv":
				if file == "" {
					file = ".env"
				}
				syncers = append(syncers, syncer.NewDotenv(file))
			case "github":
				token := os.Getenv("GITHUB_TOKEN")
				if token == "" {
					return skret.NewError(skret.ExitConfigError, "sync: GITHUB_TOKEN env var required", nil)
				}
				repos := strings.Split(githubRepo, ",")
				for _, r := range repos {
					r = strings.TrimSpace(r)
					if r == "" {
						continue
					}
					parts := strings.SplitN(r, "/", 2)
					if len(parts) != 2 {
						return skret.NewError(skret.ExitConfigError, fmt.Sprintf("sync: invalid repo format %q, must be owner/repo", r), nil)
					}
					syncers = append(syncers, syncer.NewGitHub(parts[0], parts[1], token, ""))
				}
				if len(syncers) == 0 {
					return skret.NewError(skret.ExitConfigError, "sync: --github-repo requires at least one repository", nil)
				}
			default:
				return skret.NewError(skret.ExitConfigError, fmt.Sprintf("sync: unknown target %q", to), nil)
			}

			for _, s := range syncers {
				if err := s.Sync(ctx, secrets); err != nil {
					return skret.NewError(skret.ExitNetworkError, fmt.Sprintf("sync failed for %s", s.Name()), err)
				}
				cmd.Printf("Synced %d secrets to %s\n", len(secrets), s.Name())
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&to, "to", "dotenv", "sync target (dotenv, github)")
	cmd.Flags().StringVar(&file, "file", "", "output file path (for dotenv)")
	cmd.Flags().StringVar(&githubRepo, "github-repo", "", "GitHub repository (owner/repo, comma separated)")

	return cmd
}
