package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/n24q02m/skret/pkg/skret"
)

// pruneTarget is a fake GitHub Actions secrets API: it lists `listed`
// (name -> updated_at), accepts sealed PUTs and DELETEs, and records every
// mutation. deleteStatus is what each DELETE answers.
type pruneTarget struct {
	mu           sync.Mutex
	listed       map[string]string
	deleteStatus int
	puts         []string
	deletes      []string
	requests     int
}

func newPruneTarget(t *testing.T, listed map[string]string, deleteStatus int) (*pruneTarget, *httptest.Server) {
	t.Helper()
	pt := &pruneTarget{listed: listed, deleteStatus: deleteStatus}
	pub := testPublicKeyB64(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pt.mu.Lock()
		defer pt.mu.Unlock()
		pt.requests++
		name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/actions/secrets/public-key"):
			_, _ = w.Write([]byte(`{"key_id":"1","key":"` + pub + `"}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/actions/secrets"):
			type entry struct {
				Name      string `json:"name"`
				UpdatedAt string `json:"updated_at"`
			}
			entries := make([]entry, 0, len(pt.listed))
			for n, at := range pt.listed {
				entries = append(entries, entry{Name: n, UpdatedAt: at})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": len(entries), "secrets": entries})
		case r.Method == http.MethodPut:
			pt.puts = append(pt.puts, name)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete:
			pt.deletes = append(pt.deletes, name)
			w.WriteHeader(pt.deleteStatus)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)
	return pt, srv
}

func isolateSyncHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}
}

func TestSyncPrune_DefaultOffNeverDeletes(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{"ALPHA": "2026-01-01T00:00:00Z", "ORPHAN": "2026-07-17T00:00:00Z"}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	withGithubTarget(t, dir, "o/r", srv.URL, false)
	t.Setenv("GITHUB_TOKEN", "tok")

	runSyncCmd(t, dir, nil)
	assert.Equal(t, []string{"ALPHA"}, pt.puts)
	assert.Empty(t, pt.deletes, "without --prune nothing is ever deleted")
}

func TestSyncPrune_DryRunListsOrphansAndWritesNothing(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{
		"ALPHA":   "2026-01-01T00:00:00Z",
		"ORPHAN":  "2026-07-17T00:00:00Z",
		"A_STALE": "2026-07-27T00:00:00Z",
	}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1", "BETA": "2"})
	withGithubTarget(t, dir, "o/r", srv.URL, false)
	t.Setenv("GITHUB_TOKEN", "tok")

	out := runSyncCmd(t, dir, []string{"--dry-run", "--prune"})
	assert.Contains(t, out, "[dry-run] github: would write 2 secret(s): ALPHA, BETA")
	assert.Contains(t, out, "[dry-run] github: would delete: A_STALE (2026-07-27T00:00:00Z)")
	assert.Contains(t, out, "[dry-run] github: would delete: ORPHAN (2026-07-17T00:00:00Z)")
	assert.Less(t, strings.Index(out, "A_STALE"), strings.Index(out, "ORPHAN"), "orphans print sorted")
	assert.NotContains(t, out, "would delete: ALPHA")
	assert.Empty(t, pt.puts)
	assert.Empty(t, pt.deletes)
	assertNoSyncStateFiles(t)
}

func TestSyncPrune_DryRunNoOrphans(t *testing.T) {
	isolateSyncHome(t)
	_, srv := newPruneTarget(t, map[string]string{"ALPHA": "2026-01-01T00:00:00Z"}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	withGithubTarget(t, dir, "o/r", srv.URL, false)
	t.Setenv("GITHUB_TOKEN", "tok")

	out := runSyncCmd(t, dir, []string{"--dry-run", "--prune"})
	assert.Contains(t, out, "[dry-run] github: would delete 0 secret(s)")
}

func TestSyncPrune_DeletesOnlyOrphansAfterWriting(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{
		"ALPHA":  "2026-01-01T00:00:00Z",
		"ORPHAN": "2026-07-17T00:00:00Z",
	}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1", "BETA": "2"})
	withGithubTarget(t, dir, "o/r", srv.URL, false)
	t.Setenv("GITHUB_TOKEN", "tok")

	out := runSyncCmd(t, dir, []string{"--prune"})
	assert.ElementsMatch(t, []string{"ALPHA", "BETA"}, pt.puts)
	assert.Equal(t, []string{"ORPHAN"}, pt.deletes)
	assert.Contains(t, out, "Synced 2 secrets to github")
	assert.Contains(t, out, "Pruned 1 secret(s) from github: ORPHAN")
}

func TestSyncPrune_SourceIsTheWholeSetNotTheWriteSet(t *testing.T) {
	isolateSyncHome(t)
	// ALPHA already exists and no-overwrite skips writing it; it is still a
	// source key, so prune must keep it.
	pt, srv := newPruneTarget(t, map[string]string{
		"ALPHA":  "2026-01-01T00:00:00Z",
		"ORPHAN": "2026-07-17T00:00:00Z",
	}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1", "BETA": "2"})
	withGithubTarget(t, dir, "o/r", srv.URL, true)
	t.Setenv("GITHUB_TOKEN", "tok")

	runSyncCmd(t, dir, []string{"--prune"})
	assert.Equal(t, []string{"BETA"}, pt.puts)
	assert.Equal(t, []string{"ORPHAN"}, pt.deletes)
}

func TestSyncPrune_RefusesEmptySource(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{"ORPHAN": "2026-07-17T00:00:00Z"}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{})
	withGithubTarget(t, dir, "o/r", srv.URL, false)
	t.Setenv("GITHUB_TOKEN", "tok")

	for _, args := range [][]string{{"--prune"}, {"--prune", "--dry-run"}} {
		err := runSyncCmdErr(t, dir, args)
		require.Error(t, err, "args %v", args)
		var se *skret.Error
		require.True(t, errors.As(err, &se))
		assert.Equal(t, skret.ExitConfigError, se.Code)
		assert.Contains(t, err.Error(), "empty source")
	}
	assert.Zero(t, pt.requests, "an empty source must stop before any target request")
}

func TestSyncPrune_RejectsTargetThatCannotDelete(t *testing.T) {
	isolateSyncHome(t)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	withDotenvTarget(t, dir, "out.env", false)

	err := runSyncCmdErr(t, dir, []string{"--prune"})
	require.Error(t, err)
	var se *skret.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, skret.ExitConfigError, se.Code)
	assert.Contains(t, err.Error(), "dotenv")
	_, statErr := os.Stat(filepath.Join(dir, "out.env"))
	assert.True(t, os.IsNotExist(statErr), "an unsupported --prune target must fail before any write")
}

func TestSyncPrune_DeleteFailureExitsNetworkError(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{"ORPHAN": "2026-07-17T00:00:00Z"}, http.StatusForbidden)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	withGithubTarget(t, dir, "o/r", srv.URL, false)
	t.Setenv("GITHUB_TOKEN", "tok")

	err := runSyncCmdErr(t, dir, []string{"--prune"})
	require.Error(t, err)
	var se *skret.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, skret.ExitNetworkError, se.Code)
	assert.Contains(t, err.Error(), "prune failed for github")
	assert.Equal(t, []string{"ALPHA"}, pt.puts, "the write lands before prune runs")
}

func TestSyncPrune_ListFailureExitsBeforeDelete(t *testing.T) {
	isolateSyncHome(t)
	var deletes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/actions/secrets"):
			w.WriteHeader(http.StatusForbidden)
		case r.Method == http.MethodDelete:
			deletes++
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	defer srv.Close()
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	withGithubTarget(t, dir, "o/r", srv.URL, false)
	t.Setenv("GITHUB_TOKEN", "tok")

	err := runSyncCmdErr(t, dir, []string{"--prune", "--dry-run"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list existing")
	assert.Zero(t, deletes)
}

func TestSyncPrune_JSONReportsPrunedCount(t *testing.T) {
	isolateSyncHome(t)
	_, srv := newPruneTarget(t, map[string]string{"ORPHAN": "2026-07-17T00:00:00Z"}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	withGithubTarget(t, dir, "o/r", srv.URL, false)
	t.Setenv("GITHUB_TOKEN", "tok")

	out := runSyncCmd(t, dir, []string{"--prune", "--format", "json"})
	start := strings.Index(out, "[")
	require.GreaterOrEqual(t, start, 0, out)
	var results []SyncResult
	require.NoError(t, json.Unmarshal([]byte(out[start:]), &results))
	require.Len(t, results, 1)
	assert.Equal(t, 1, results[0].Synced)
	assert.Equal(t, 1, results[0].Pruned)
}

func TestSyncPrune_NothingToPrune(t *testing.T) {
	isolateSyncHome(t)
	pt, srv := newPruneTarget(t, map[string]string{"ALPHA": "2026-01-01T00:00:00Z"}, http.StatusNoContent)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	withGithubTarget(t, dir, "o/r", srv.URL, false)
	t.Setenv("GITHUB_TOKEN", "tok")

	out := runSyncCmd(t, dir, []string{"--prune"})
	assert.Contains(t, out, "Pruned 0 secret(s) from github")
	assert.Empty(t, pt.deletes)
}

func TestSyncPrune_ListFailureAfterWriteExitsNetworkError(t *testing.T) {
	isolateSyncHome(t)
	pub := testPublicKeyB64(t)
	var puts, deletes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/actions/secrets/public-key"):
			_, _ = w.Write([]byte(`{"key_id":"1","key":"` + pub + `"}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/actions/secrets"):
			w.WriteHeader(http.StatusForbidden)
		case r.Method == http.MethodPut:
			puts++
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete:
			deletes++
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	defer srv.Close()
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	withGithubTarget(t, dir, "o/r", srv.URL, false)
	t.Setenv("GITHUB_TOKEN", "tok")

	err := runSyncCmdErr(t, dir, []string{"--prune"})
	require.Error(t, err)
	var se *skret.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, skret.ExitNetworkError, se.Code)
	assert.Contains(t, err.Error(), "prune failed for github")
	assert.Equal(t, 1, puts)
	assert.Zero(t, deletes)
}
