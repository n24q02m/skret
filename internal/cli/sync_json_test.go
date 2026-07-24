package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSyncOptions_Run_JSONFormat_Dotenv covers the single-target case:
// --format json replaces the "Synced N secrets to X" stderr line with a
// SyncResult array on stdout. Synced (not a per-key added/updated/deleted
// breakdown) is what syncer.Syncer can actually report -- see the SyncResult
// doc comment in sync.go.
func TestSyncOptions_Run_JSONFormat_Dotenv(t *testing.T) {
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1", "BETA": "2"})
	withDotenvTarget(t, dir, "out.env", false)

	out := runSyncCmd(t, dir, []string{"--format", "json"})

	var results []SyncResult
	require.NoError(t, json.Unmarshal([]byte(out), &results), "output must be pure JSON: %s", out)
	require.Len(t, results, 1)
	assert.Equal(t, "dotenv", results[0].Target)
	assert.Equal(t, 2, results[0].Synced)
	assert.NotContains(t, out, "Synced 2 secrets to dotenv",
		"json mode must replace the human status line, not print both")
}

// TestSyncOptions_Run_JSONFormat_MultipleTargets covers syncing to more than
// one target in a single invocation: the array must carry one SyncResult per
// target, in target order. Both targets are declared in .skret.yaml (rather
// than via --to flags) so the github target's base_url can point at the
// httptest server instead of the real GitHub API.
func TestSyncOptions_Run_JSONFormat_MultipleTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/actions/secrets/public-key"):
			_, _ = w.Write([]byte(`{"key_id":"1","key":"` + testPublicKeyB64(t) + `"}`))
		case r.Method == http.MethodPut:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	appendSyncTarget(t, dir, fmt.Sprintf(`sync:
  targets:
    - type: dotenv
      file: out.env
    - type: github
      repo: o/r
      base_url: %s
`, srv.URL))
	t.Setenv("GITHUB_TOKEN", "tok")

	out := runSyncCmd(t, dir, []string{"--format", "json"})

	var results []SyncResult
	require.NoError(t, json.Unmarshal([]byte(out), &results), "output must be pure JSON: %s", out)
	require.Len(t, results, 2)
	assert.Equal(t, "dotenv", results[0].Target)
	assert.Equal(t, 1, results[0].Synced)
	assert.Equal(t, "github", results[1].Target)
	assert.Equal(t, 1, results[1].Synced)
}

// TestSyncOptions_Run_TableFormatUnchanged locks in that the default (no
// --format, table) output is exactly what it was before this change.
func TestSyncOptions_Run_TableFormatUnchanged(t *testing.T) {
	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "1"})
	withDotenvTarget(t, dir, "out.env", false)

	out := runSyncCmd(t, dir, nil)
	assert.Equal(t, "Synced 1 secrets to dotenv\n", out)
}
