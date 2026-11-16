package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/n24q02m/skret/internal/syncer"
	"github.com/n24q02m/skret/pkg/skret"
)

// A target declared in .skret.yaml without sources syncs the whole
// environment path. Pruning against that implicit set would delete every
// target secret the path happens not to hold, so --prune refuses it before
// any provider or target request.
func TestSyncPrune_RefusesDeclaredTargetWithoutSources(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{"ORPHAN": "2026-07-17T00:00:00Z"}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	withGithubTarget(t, dir, "o/r", srv.URL, false)
	t.Setenv("GITHUB_TOKEN", "tok")

	for _, args := range [][]string{
		{"--prune"},
		{"--prune", "--dry-run"},
		{"--to=github", "--prune"},
		{"--to=github", "--prune", "--no-overwrite"},
	} {
		err := runSyncCmdErr(t, dir, args)
		requireExit(t, err, skret.ExitConfigError)
		assert.True(t, errors.Is(err, syncer.ErrPruneImplicitSources), "args %v: %v", args, err)
		assert.Contains(t, err.Error(), `github target "o/r"`, "args %v", args)
		assert.Contains(t, err.Error(), "sources", "args %v", args)
	}
	assert.Zero(t, pt.requests, "the refusal must come before any target request")
}

// Without --prune the same declaration keeps syncing the environment path.
func TestSyncPrune_DeclaredTargetWithoutSourcesStillSyncs(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	withGithubTarget(t, dir, "o/r", srv.URL, false)
	t.Setenv("GITHUB_TOKEN", "tok")

	runSyncCmd(t, dir, nil)
	assert.Equal(t, []string{"ALPHA"}, pt.puts)
}

// A target built from --to/--github-repo has no .skret.yaml declaration to
// make explicit; its source is the environment path the operator named on
// the command line, so --prune keeps accepting it.
func TestSyncPrune_FlagTargetNeedsNoSources(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "tok")
	o := &syncOptions{to: "github", githubRepo: "o/r", prune: true}
	targets, err := o.resolveTargets(nil)
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, "o/r", targets[0].Fields["repo"])
	assert.Nil(t, targets[0].Sources)
}

// The provisioning run: no-overwrite with every source name already on the
// target writes nothing, still prunes the orphan, and reports synced 0.
func TestSyncPrune_NoOverwriteWithEverythingPresentStillPrunes(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{
		"ALPHA":  "2026-01-01T00:00:00Z",
		"ORPHAN": "2026-07-17T00:00:00Z",
	}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	withGithubPruneTarget(t, dir, srv.URL, true)
	t.Setenv("GITHUB_TOKEN", "tok")

	out := runSyncCmd(t, dir, []string{"--prune", "--dry-run"})
	assert.Contains(t, out, "Skipped 1 existing secret(s) for github (no-overwrite)")
	assert.Contains(t, out, "[dry-run] github: would write 0 secret(s)")
	assert.Contains(t, out, "[dry-run] github: would delete: ORPHAN (2026-07-17T00:00:00Z)")
	assert.Empty(t, pt.deletes)

	out = runSyncCmd(t, dir, []string{"--prune", "--format", "json"})
	start := strings.Index(out, "[")
	require.GreaterOrEqual(t, start, 0, out)
	var results []SyncResult
	require.NoError(t, json.Unmarshal([]byte(out[start:]), &results))
	require.Len(t, results, 1)
	assert.Equal(t, 0, results[0].Synced)
	assert.Equal(t, 1, results[0].Pruned)
	assert.Empty(t, pt.puts, "no-overwrite never rewrites a present name")
	assert.Equal(t, []string{"ORPHAN"}, pt.deletes)
}
