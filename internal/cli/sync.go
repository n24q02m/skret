package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
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
	noOverwrite   bool
	rotate        bool
	dryRun        bool
	format        string
}

// saveSyncState is kept indirect so focused tests can exercise persistence
// failures at each acknowledgement boundary without touching real targets.
var saveSyncState = syncer.SaveSyncState

// SyncResult is the --format json payload for one successfully synced
// target. Batch-only targets report the full batch count; durable operations
// for per-key targets report the same count only after every key is
// acknowledged and the operation state is finalized and saved. --dry-run
// targets are not included: they write nothing.
type SyncResult struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Synced int    `json:"synced"`
	Intent string `json:"intent,omitempty"`
}

func newSyncCmd(opts *GlobalOpts) *cobra.Command {
	o := &syncOptions{global: opts}

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync secrets to external targets (dotenv, github, cloudflare)",
		Long: `Sync secrets to one or more external targets.

Targets are declared in .skret.yaml under sync.targets (github, cloudflare
worker/pages, dotenv); running 'skret sync' with no --to pushes to all of them.
--to accepts a comma-list to pick specific target types. Tokens come from
GITHUB_TOKEN / CLOUDFLARE_API_TOKEN. Use --skip-unchanged for hash-based drift.
--no-overwrite (or no_overwrite: true per target) only writes keys absent at
the target, so existing values are never overwritten. Use --rotate for an
explicit controlled overwrite of selected source keys; --rotate overrides a
target's no_overwrite setting but cannot combine with --no-overwrite.
--dry-run prints what each target would write and exits without writing anything
or saving sync state.`,
		Example: `  skret sync
  skret sync --to=github,cloudflare
  skret sync --to=github --github-repo=owner/repo --skip-unchanged
  skret sync --no-overwrite
  skret sync --rotate
  skret sync --config deploy/sync/knowledgeprism.skret.yaml --dry-run`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}

	cmd.Flags().StringVar(&o.to, "to", "", "sync target(s), comma-separated (dotenv, github, cloudflare); default: .skret.yaml sync.targets, else dotenv")
	cmd.Flags().StringVar(&o.file, "file", "", "output file path (for dotenv)")
	cmd.Flags().StringVar(&o.githubRepo, "github-repo", "", "GitHub repository (owner/repo, comma separated)")
	cmd.Flags().BoolVar(&o.skipUnchanged, "skip-unchanged", false, "skip secrets whose value is unchanged since the previous successful sync (drift detection)")
	cmd.Flags().BoolVar(&o.noOverwrite, "no-overwrite", false, "only write secrets absent at the target; never overwrite an existing one (forces no_overwrite for every target)")
	cmd.Flags().BoolVar(&o.rotate, "rotate", false, "explicitly overwrite selected target values and record rotation state (conflicts with --no-overwrite)")
	cmd.Flags().BoolVar(&o.dryRun, "dry-run", false, "print what each target would write and exit; issues no write request and saves no state")
	cmd.Flags().StringVar(&o.format, "format", "table", "output format (table, json)")

	cmd.AddCommand(newSyncPlanServerCmd())

	return cmd
}

func (o *syncOptions) run(cmd *cobra.Command) error {
	if o.rotate && o.noOverwrite {
		return skret.NewError(skret.ExitConfigError, "sync: cannot combine --rotate and --no-overwrite", nil)
	}

	sc, err := loadSyncConfig(o.global)
	if err != nil {
		return skret.NewError(skret.ExitConfigError, "sync: load config failed", err)
	}

	targets, err := o.resolveTargets(sc)
	if err != nil {
		return err
	}
	syncers, err := syncer.Build(targets)
	if err != nil {
		return skret.NewError(skret.ExitConfigError, "sync: build targets", err)
	}
	if err := syncer.ValidateTargetIdentities(targets); err != nil {
		return skret.NewError(skret.ExitConfigError, "sync: validate targets", err)
	}

	resolved, p, err := loadProvider(o.global)
	if err != nil {
		return err
	}
	defer p.Close()
	warnIfPathMangled(cmd, resolved)

	ctx := context.Background()
	secrets, err := p.List(ctx, resolved.Path)
	if err != nil {
		return skret.NewError(skret.ExitProviderError, "sync: list secrets failed", err)
	}
	secrets = filterExcluded(secrets, resolved.Path, resolved.Exclude)

	if len(secrets) == 0 {
		cmd.PrintErrln("No secrets found to sync. Use 'skret set' to add a secret.")
	}

	results := make([]SyncResult, 0, len(syncers))
	for i, s := range syncers {
		tc := targets[i]
		toSync := secrets
		noOv := !o.rotate && (tc.NoOverwrite || o.noOverwrite)

		// Rotation and all external provider mutations use a durable state
		// journal. Stateless mode remains available for local dotenv writes.
		var state *syncer.SyncState
		var operationID string
		journalByDefault := s.Name() == "github" || s.Name() == "cloudflare"
		if journalByDefault || o.rotate || (o.skipUnchanged && !noOv) {
			stateID := targetStateID(s, tc)
			if !o.dryRun {
				release, lockErr := syncer.AcquireTargetLock(s.Name(), stateID)
				if lockErr != nil {
					return skret.NewError(skret.ExitGenericError, "sync: lock target", lockErr)
				}
				defer func(release func() error) { _ = release() }(release)
			}
			state, err = syncer.LoadSyncState(s.Name(), stateID)
			if err != nil {
				return skret.NewError(skret.ExitGenericError, "sync: load state failed", err)
			}
			if o.skipUnchanged && !o.rotate && !noOv {
				toSync = state.FilterUnchanged(secrets)
				if skipped := len(secrets) - len(toSync); skipped > 0 {
					cmd.PrintErrf("Skipped %d unchanged secret(s) for %s\n", skipped, s.Name())
				}
			}
		}

		if noOv {
			kept, skippedExisting, ferr := syncer.FilterAbsent(ctx, s, toSync)
			if ferr != nil {
				return skret.NewError(skret.ExitConfigError, fmt.Sprintf("sync: %s", s.Name()), ferr)
			}
			toSync = kept
			if skippedExisting > 0 {
				cmd.PrintErrf("Skipped %d existing secret(s) for %s (no-overwrite)\n", skippedExisting, s.Name())
			}
		}

		if o.dryRun {
			names := make([]string, 0, len(toSync))
			for _, sec := range toSync {
				names = append(names, syncer.SecretName(sec.Key))
			}
			sort.Strings(names)
			if len(names) == 0 {
				cmd.PrintErrf("[dry-run] %s: would write 0 secret(s)\n", s.Name())
			} else {
				cmd.PrintErrf("[dry-run] %s: would write %d secret(s): %s\n", s.Name(), len(names), strings.Join(names, ", "))
			}
			continue
		}
		recoveredState := false
		if journalByDefault && state != nil && state.RequiresReconciliation() {
			return skret.NewError(
				skret.ExitNetworkError,
				fmt.Sprintf("sync: %s operation requires provider reconciliation before retry", s.Name()),
				syncer.ErrOperationNeedsReconciliation,
			)
		}
		if state != nil && syncStateNeedsRecovery(state) {
			if err := state.FinalizeOperation(state.OperationID, time.Now().UTC()); err != nil {
				return skret.NewError(skret.ExitGenericError, "sync: recover operation", err)
			}
			if err := saveSyncState(state); err != nil {
				return skret.NewError(skret.ExitGenericError, "sync: save recovered state", err)
			}
			recoveredState = true
			if journalByDefault {
				toSync = state.FilterUnchanged(toSync)
			}
		}

		if state != nil && len(toSync) > 0 {
			recoveredState = false
			if journalByDefault && state.RequiresReconciliation() {
				return skret.NewError(
					skret.ExitNetworkError,
					fmt.Sprintf("sync: %s operation requires provider reconciliation before retry", s.Name()),
					syncer.ErrOperationNeedsReconciliation,
				)
			}
			operationID, err = syncer.NewOperationID()
			if err != nil {
				return skret.NewError(skret.ExitGenericError, "sync: create operation", err)
			}
			if o.rotate {
				err = state.BeginOperationWithIntent(operationID, syncer.OperationIntentRotate, toSync, time.Now().UTC())
			} else {
				err = state.BeginOperation(operationID, toSync, time.Now().UTC())
			}
			if err != nil {
				return skret.NewError(skret.ExitGenericError, "sync: begin operation", err)
			}
			state.OperationMethod = mutationMethod(s, tc)
			state.SourceIdentity = resolved.Provider + ":" + resolved.Path
			state.SourceDigest = syncer.SourceDigest(toSync)
			if err := saveSyncState(state); err != nil {
				return skret.NewError(skret.ExitGenericError, "sync: save state failed", err)
			}
		}
		durablePerKey := false
		if state != nil && operationID != "" {
			if keyer, ok := s.(syncer.PerKeySyncer); ok {
				durablePerKey = true
				if err := syncPerKeyOperation(ctx, keyer, state, operationID, toSync); err != nil {
					exitCode := skret.ExitNetworkError
					var journalErr *syncJournalError
					if errors.As(err, &journalErr) {
						exitCode = skret.ExitGenericError
					}
					return skret.NewError(exitCode, fmt.Sprintf("sync failed for %s", s.Name()), err)
				}
			}
		}
		if !durablePerKey {
			if err := s.Sync(ctx, toSync); err != nil {
				// dotenv writes a local file only -- a failure there is I/O, not
				// network. github/cloudflare stay ExitNetworkError (audit I2).
				exitCode := skret.ExitNetworkError
				if tc.Type == "dotenv" {
					exitCode = skret.ExitGenericError
				}
				if state != nil && operationID != "" {
					journalErr := state.RecordNeedsReconciliation(operationID, toSync, time.Now().UTC())
					if journalErr == nil {
						journalErr = saveSyncState(state)
					}
					if journalErr != nil {
						return skret.NewError(exitCode, fmt.Sprintf("sync failed for %s; state journal failed", s.Name()), journalErr)
					}
				}
				return skret.NewError(exitCode, fmt.Sprintf("sync failed for %s", s.Name()), err)
			}
		}

		// Durable state must be finalized and persisted before reporting target
		// success. Per-key targets already journaled each acknowledgement and
		// finalized in syncPerKeyOperation.
		if state != nil {
			if operationID != "" && !durablePerKey {
				if err := state.RecordSuccess(operationID, toSync, time.Now().UTC()); err != nil {
					return skret.NewError(skret.ExitGenericError, "sync: record success", err)
				}
			}
			if !durablePerKey && !recoveredState {
				if err := saveSyncState(state); err != nil {
					return skret.NewError(skret.ExitGenericError, "sync: save state failed", err)
				}
			}
		}

		switch {
		case o.format == "json":
			result := SyncResult{Source: resolved.Path, Target: s.Name(), Synced: len(toSync)}
			if o.rotate {
				result.Intent = syncer.OperationIntentRotate
			}
			results = append(results, result)
		case o.rotate:
			cmd.PrintErrf("Rotated %d secrets to %s\n", len(toSync), s.Name())
		default:
			cmd.PrintErrf("Synced %d secrets to %s\n", len(toSync), s.Name())
		}
	}

	if o.format == "json" {
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return skret.NewError(skret.ExitGenericError, "sync: encode result", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
	}

	return nil
}

type syncJournalError struct {
	err error
}

func (e *syncJournalError) Error() string { return e.err.Error() }

func (e *syncJournalError) Unwrap() error { return e.err }

func syncStateNeedsRecovery(state *syncer.SyncState) bool {
	if state == nil || state.OperationID == "" {
		return false
	}
	if state.Phase != syncer.OperationPhasePending &&
		(state.Phase != "" || state.CompletedAt != nil) {
		return false
	}
	owned := 0
	for _, outcome := range state.Outcomes {
		if outcome.OperationID != state.OperationID {
			continue
		}
		owned++
		if outcome.Status != syncer.OutcomeSucceeded {
			return false
		}
	}
	return owned > 0
}

// syncPerKeyOperation writes and journals one target key at a time. A failed
// key is marked for reconciliation and stops the operation, leaving every
// unattempted key pending. Each successful acknowledgement is persisted before
// the next provider call so a process interruption cannot turn an earlier
// provider success into an unjournaled global result.
func syncPerKeyOperation(
	ctx context.Context,
	target syncer.PerKeySyncer,
	state *syncer.SyncState,
	operationID string,
	secrets []*provider.Secret,
) error {
	for _, secret := range secrets {
		if err := target.SyncKey(ctx, secret); err != nil {
			now := time.Now().UTC()
			if journalErr := state.RecordKeyNeedsReconciliation(operationID, secret, now); journalErr != nil {
				return &syncJournalError{err: fmt.Errorf("record key reconciliation: %w", journalErr)}
			}
			if journalErr := saveSyncState(state); journalErr != nil {
				return &syncJournalError{err: fmt.Errorf("save key reconciliation: %w", journalErr)}
			}
			return err
		}

		now := time.Now().UTC()
		if err := state.RecordKeySuccess(operationID, secret, now); err != nil {
			return &syncJournalError{err: fmt.Errorf("record key success: %w", err)}
		}
		if err := saveSyncState(state); err != nil {
			return &syncJournalError{err: fmt.Errorf("save key success: %w", err)}
		}
	}

	if err := state.FinalizeOperation(operationID, time.Now().UTC()); err != nil {
		return &syncJournalError{err: fmt.Errorf("finalize operation: %w", err)}
	}
	if err := saveSyncState(state); err != nil {
		return &syncJournalError{err: fmt.Errorf("save finalized operation: %w", err)}
	}
	return nil
}

// filterExcluded drops secrets whose resolved env-var name is in the
// top-level .skret.yaml exclude list, so `sync` never pushes an excluded
// secret to an external target. Mirrors exec.BuildEnv's matching semantics
// exactly (uppercased exclude entries matched against the final
// KeyToEnvName output) so exclude behaves consistently across run/env/sync.
func filterExcluded(secrets []*provider.Secret, pathPrefix string, exclude []string) []*provider.Secret {
	if len(exclude) == 0 {
		return secrets
	}

	excludeSet := make(map[string]bool, len(exclude))
	for _, e := range exclude {
		excludeSet[strings.ToUpper(e)] = true
	}

	out := make([]*provider.Secret, 0, len(secrets))
	for _, s := range secrets {
		if excludeSet[KeyToEnvName(s.Key, pathPrefix)] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// loadSyncConfig returns the .skret.yaml sync block, honoring --config, or
// nil when there is no config file (flags-only mode).
func loadSyncConfig(opts *GlobalOpts) (*config.SyncConfig, error) {
	cfgPath, derr := resolveConfigFile(opts)
	if errors.Is(derr, config.ErrConfigNotFound) {
		return nil, nil // no config -> declared targets absent; flags-only
	}
	if derr != nil {
		return nil, derr
	}
	cfg, lerr := config.Load(cfgPath)
	if lerr != nil {
		return nil, lerr
	}
	return cfg.Sync, nil
}

// resolveTargets merges declared .skret.yaml sync.targets with CLI overrides.
// If --to is set, each requested type is resolved independently, in --to
// order: a type with one or more matching sync.targets entries uses those;
// a type with no matching entry falls back to flags (one-off overrides, and
// backwards compat: --to=github --github-repo=o/r, --to=dotenv). This keeps
// a mixed --to=github,dotenv from silently dropping dotenv just because
// github matched a declared target. If --to is empty, every declared
// sync.targets entry is built. With no declared targets and no --to, sync
// falls back to the legacy dotenv default.
func (o *syncOptions) resolveTargets(sc *config.SyncConfig) ([]syncer.TargetConfig, error) {
	var wantOrder []string
	want := map[string]bool{}
	if o.to != "" {
		for _, t := range strings.Split(o.to, ",") {
			if t = strings.TrimSpace(t); t != "" && !want[t] {
				want[t] = true
				wantOrder = append(wantOrder, t)
			}
		}
	}

	var out []syncer.TargetConfig
	if len(want) > 0 {
		for _, typ := range wantOrder {
			var declared []config.SyncTarget
			if sc != nil {
				for _, t := range sc.Targets {
					if t.Type == typ {
						declared = append(declared, t)
					}
				}
			}
			if len(declared) > 0 {
				for _, t := range declared {
					out = append(out, targetFromConfig(t))
				}
				continue
			}
			tcs, err := o.targetFromFlags(typ)
			if err != nil {
				return nil, err
			}
			out = append(out, tcs...)
		}
	} else if sc != nil {
		for _, t := range sc.Targets {
			out = append(out, targetFromConfig(t))
		}
	}

	if len(out) == 0 {
		// Legacy default: dotenv.
		out = append(out, syncer.TargetConfig{Type: "dotenv", Fields: map[string]string{"file": o.file}})
	}
	return out, nil
}

// targetFromConfig converts a declared .skret.yaml sync target into a
// syncer.TargetConfig, resolving its token from the environment and
// expanding ${VAR} references in account (e.g. cloudflare's account id).
func targetFromConfig(t config.SyncTarget) syncer.TargetConfig {
	fields := map[string]string{
		"repo":     t.Repo,
		"worker":   t.Worker,
		"pages":    t.Pages,
		"account":  os.ExpandEnv(t.Account),
		"file":     t.File,
		"base_url": t.BaseURL,
	}
	return syncer.TargetConfig{Type: t.Type, Fields: fields, Token: tokenForType(t.Type), NoOverwrite: t.NoOverwrite}
}

// targetFromFlags builds TargetConfigs for a --to type that has no
// sync.targets declaration, preserving the original flags-only CLI behavior.
func (o *syncOptions) targetFromFlags(typ string) ([]syncer.TargetConfig, error) {
	switch typ {
	case "dotenv":
		return []syncer.TargetConfig{{Type: "dotenv", Fields: map[string]string{"file": o.file}}}, nil
	case "github":
		token := os.Getenv("GITHUB_TOKEN")
		var errs []error
		if token == "" {
			errs = append(errs, errors.New("sync: GITHUB_TOKEN env var required"))
		}

		var tcs []syncer.TargetConfig
		hasRepoErr := false
		for _, r := range strings.Split(o.githubRepo, ",") {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			owner, repo, found := strings.Cut(r, "/")
			if !found || owner == "" || repo == "" {
				errs = append(errs, fmt.Errorf("sync: invalid repo format %q, must be owner/repo", r))
				hasRepoErr = true
				continue
			}
			tcs = append(tcs, syncer.TargetConfig{Type: "github", Fields: map[string]string{"repo": r}, Token: token})
		}
		if len(tcs) == 0 && !hasRepoErr {
			errs = append(errs, errors.New("sync: --github-repo requires at least one repository"))
		}

		// Report every missing/invalid requirement in one error instead of
		// making the operator fix one, re-run, and discover the next one
		// (audit finding I7).
		if len(errs) > 0 {
			return nil, skret.NewError(skret.ExitConfigError, "sync: github target misconfigured", errors.Join(errs...))
		}
		return tcs, nil
	case "cloudflare":
		return nil, skret.NewError(skret.ExitConfigError, "sync: cloudflare target requires a sync.targets entry in .skret.yaml", nil)
	default:
		return nil, skret.NewError(skret.ExitConfigError, fmt.Sprintf("sync: unknown target %q", typ), nil)
	}
}

// tokenForType resolves a target type's auth token from the environment.
// Never logged; dotenv has no token.
func tokenForType(typ string) string {
	switch typ {
	case "github":
		return os.Getenv("GITHUB_TOKEN")
	case "cloudflare":
		return os.Getenv("CLOUDFLARE_API_TOKEN")
	}
	return ""
}

func mutationMethod(s syncer.Syncer, tc syncer.TargetConfig) string {
	switch s.Name() {
	case "github":
		return "PUT"
	case "cloudflare":
		if tc.Fields["pages"] != "" {
			return "PATCH"
		}
		return "PUT"
	default:
		return ""
	}
}

// targetStateID returns the per-target identifier used to scope the sync
// state file, derived from the resolved TargetConfig. Dotenv uses the
// output file path; GitHub uses the repo string; Cloudflare uses
// "worker/<name>" or "pages/<name>".
func targetStateID(s syncer.Syncer, tc syncer.TargetConfig) string {
	switch s.Name() {
	case "dotenv":
		if file := tc.Fields["file"]; file != "" {
			return file
		}
		return ".env"
	case "github":
		return tc.Fields["repo"]
	case "cloudflare":
		if w := tc.Fields["worker"]; w != "" {
			return "worker/" + w
		}
		return "pages/" + tc.Fields["pages"]
	}
	return ""
}

// syncerStateID returns the per-target identifier used to scope the sync
// state file for the legacy flags-only dotenv/github path.
func syncerStateID(s syncer.Syncer, file, githubRepo string) string {
	if s.Name() == "dotenv" {
		if file == "" {
			return ".env"
		}
		return file
	}
	return githubRepo
}

// buildSyncers initializes the requested sync targets from flags only
// (legacy helper; retained for callers/tests exercising the flags-only path).
func buildSyncers(to, file, githubRepo string) ([]syncer.Syncer, error) {
	o := &syncOptions{to: to, file: file, githubRepo: githubRepo}
	targets, err := o.resolveTargets(nil)
	if err != nil {
		return nil, err
	}
	syncers, err := syncer.Build(targets)
	if err != nil {
		return nil, skret.NewError(skret.ExitConfigError, "sync: build targets", err)
	}
	return syncers, nil
}
