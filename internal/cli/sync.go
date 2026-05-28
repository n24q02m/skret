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

type syncOptions struct {
	global        *GlobalOpts
	to            string
	file          string
	githubRepo    string
	skipUnchanged bool
}

func newSyncCmd(opts *GlobalOpts) *cobra.Command {
	o := &syncOptions{global: opts}

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync secrets to external targets (dotenv, github)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}

	cmd.Flags().StringVar(&o.to, "to", "dotenv", "sync target (dotenv, github)")
	cmd.Flags().StringVar(&o.file, "file", "", "output file path (for dotenv)")
	cmd.Flags().StringVar(&o.githubRepo, "github-repo", "", "GitHub repository (owner/repo, comma separated)")
	cmd.Flags().BoolVar(&o.skipUnchanged, "skip-unchanged", false, "skip secrets whose value is unchanged since the previous successful sync (drift detection)")

	return cmd
}

func (o *syncOptions) run(cmd *cobra.Command) error {
	resolved, p, err := loadProvider(o.global)
	if err != nil {
		return err
	}
	defer p.Close()

	ctx := context.Background()
	secrets, err := p.List(ctx, resolved.Path)
	if err != nil {
		return skret.NewError(skret.ExitProviderError, "sync: list secrets failed", err)
	}

	syncers, err := o.buildSyncers()
	if err != nil {
		return err
	}

	for _, s := range syncers {
		toSync := secrets
		var state *syncer.SyncState
		if o.skipUnchanged {
			stateID := o.stateID(s)
			state, err = syncer.LoadSyncState(s.Name(), stateID)
			if err != nil {
				return skret.NewError(skret.ExitGenericError, "sync: load state failed", err)
			}
			toSync = state.FilterUnchanged(secrets)
			if skipped := len(secrets) - len(toSync); skipped > 0 {
				cmd.PrintErrf("Skipped %d unchanged secret(s) for %s\n", skipped, s.Name())
			}
		}

		if err := s.Sync(ctx, toSync); err != nil {
			return skret.NewError(skret.ExitNetworkError, fmt.Sprintf("sync failed for %s", s.Name()), err)
		}
		cmd.PrintErrf("Synced %d secrets to %s\n", len(toSync), s.Name())

		if o.skipUnchanged && state != nil {
			state.Update(toSync)
			if err := syncer.SaveSyncState(state); err != nil {
				return skret.NewError(skret.ExitGenericError, "sync: save state failed", err)
			}
		}
	}

	return nil
}

func (o *syncOptions) stateID(s syncer.Syncer) string {
	if s.Name() == "dotenv" {
		if o.file == "" {
			return ".env"
		}
		return o.file
	}
	return o.githubRepo
}

func (o *syncOptions) buildSyncers() ([]syncer.Syncer, error) {
	var syncers []syncer.Syncer
	switch o.to {
	case "dotenv":
		file := o.file
		if file == "" {
			file = ".env"
		}
		syncers = append(syncers, syncer.NewDotenv(file))
	case "github":
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			return nil, skret.NewError(skret.ExitConfigError, "sync: GITHUB_TOKEN env var required", nil)
		}
		repos := strings.Split(o.githubRepo, ",")
		for _, r := range repos {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			parts := strings.SplitN(r, "/", 2)
			if len(parts) != 2 {
				return nil, skret.NewError(skret.ExitConfigError, fmt.Sprintf("sync: invalid repo format %q, must be owner/repo", r), nil)
			}
			syncers = append(syncers, syncer.NewGitHub(parts[0], parts[1], token, ""))
		}
		if len(syncers) == 0 {
			return nil, skret.NewError(skret.ExitConfigError, "sync: --github-repo requires at least one repository", nil)
		}
	default:
		return nil, skret.NewError(skret.ExitConfigError, fmt.Sprintf("sync: unknown target %q", o.to), nil)
	}
	return syncers, nil
}

// syncerStateID returns the per-target identifier used to scope the sync
// state file. Dotenv uses the output file path; GitHub uses the repo string.
func syncerStateID(s syncer.Syncer, file, githubRepo string) string {
	o := &syncOptions{file: file, githubRepo: githubRepo}
	return o.stateID(s)
}

// buildSyncers initializes the requested sync targets.
func buildSyncers(to, file, githubRepo string) ([]syncer.Syncer, error) {
	o := &syncOptions{to: to, file: file, githubRepo: githubRepo}
	return o.buildSyncers()
}
