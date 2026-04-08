package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/n24q02m/skret/internal/syncer"
	"github.com/spf13/cobra"
)

func newSyncCmd() *cobra.Command {
	var (
		to         string
		file       string
		githubRepo string
	)

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync secrets to external targets (dotenv, github)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolved, p, err := loadProvider()
			if err != nil {
				return err
			}
			defer p.Close()

			ctx := context.Background()
			secrets, err := p.List(ctx, resolved.Path)
			if err != nil {
				return fmt.Errorf("sync: list secrets: %w", err)
			}

			var s syncer.Syncer
			switch to {
			case "dotenv":
				if file == "" {
					file = ".env"
				}
				s = syncer.NewDotenv(file)
			case "github":
				token := os.Getenv("GITHUB_TOKEN")
				if token == "" {
					return fmt.Errorf("sync: GITHUB_TOKEN env var required")
				}
				parts := strings.SplitN(githubRepo, "/", 2)
				if len(parts) != 2 {
					return fmt.Errorf("sync: --github-repo must be owner/repo format")
				}
				s = syncer.NewGitHub(parts[0], parts[1], token, "")
			default:
				return fmt.Errorf("sync: unknown target %q (use dotenv or github)", to)
			}

			if err := s.Sync(ctx, secrets); err != nil {
				return fmt.Errorf("sync: %w", err)
			}

			cmd.Printf("Synced %d secrets to %s\n", len(secrets), s.Name())
			return nil
		},
	}

	cmd.Flags().StringVar(&to, "to", "dotenv", "sync target (dotenv, github)")
	cmd.Flags().StringVar(&file, "file", "", "output file path (for dotenv)")
	cmd.Flags().StringVar(&githubRepo, "github-repo", "", "GitHub repository (owner/repo)")

	return cmd
}
