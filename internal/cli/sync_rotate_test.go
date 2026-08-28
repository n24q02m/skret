package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/syncer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncOptions_Run_RotateBypassesWarmSkipAndWritesAllKeys(t *testing.T) {
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}

	var putPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/actions/secrets/public-key"):
			_, _ = w.Write([]byte(`{"key_id":"1","key":"` + testPublicKeyB64(t) + `"}`))
		case r.Method == http.MethodPut:
			putPaths = append(putPaths, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("rotate must not list target keys; got %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "secret-alpha", "BETA": "secret-beta"})
	withGithubTarget(t, dir, "o/r", srv.URL, false)
	t.Setenv("GITHUB_TOKEN", "tok")

	state, err := syncer.LoadSyncState("github", "o/r")
	require.NoError(t, err)
	state.Update([]*provider.Secret{{Key: "ALPHA", Value: "secret-alpha"}, {Key: "BETA", Value: "secret-beta"}})
	require.NoError(t, syncer.SaveSyncState(state))

	out := runSyncCmd(t, dir, []string{"--rotate", "--skip-unchanged"})

	require.Len(t, putPaths, 2, "rotation must reach every source key despite warm hashes")
	assert.Contains(t, putPaths, "/repos/o/r/actions/secrets/ALPHA")
	assert.Contains(t, putPaths, "/repos/o/r/actions/secrets/BETA")
	assert.Contains(t, out, "Rotated 2 secrets to github")

	state, err = syncer.LoadSyncState("github", "o/r")
	require.NoError(t, err)
	assert.Equal(t, "rotate", state.Intent)
	assert.NotEmpty(t, state.OperationID)
	assert.Equal(t, syncer.OutcomeSucceeded, state.Outcomes["ALPHA"].Status)
	assert.Equal(t, syncer.OutcomeSucceeded, state.Outcomes["BETA"].Status)
}

func TestSyncOptions_Run_RotateOverridesTargetNoOverwrite(t *testing.T) {
	var putPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/actions/secrets/public-key"):
			_, _ = w.Write([]byte(`{"key_id":"1","key":"` + testPublicKeyB64(t) + `"}`))
		case r.Method == http.MethodPut:
			putPaths = append(putPaths, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("rotate must override target no-overwrite listing; got %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "secret-alpha"})
	withGithubTarget(t, dir, "o/r", srv.URL, true)
	t.Setenv("GITHUB_TOKEN", "tok")

	runSyncCmd(t, dir, []string{"--rotate"})

	require.Equal(t, []string{"/repos/o/r/actions/secrets/ALPHA"}, putPaths)
}

func TestSyncOptions_Run_RotateConflictsWithNoOverwriteBeforeCalls(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		t.Fatalf("target called despite rotate/no-overwrite conflict: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "secret-alpha"})
	withGithubTarget(t, dir, "o/r", srv.URL, false)
	t.Setenv("GITHUB_TOKEN", "tok")

	_, err := runSyncCmdCapture(t, dir, []string{"--rotate", "--no-overwrite"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot combine --rotate and --no-overwrite")
	assert.Zero(t, requests)
}

func TestSyncOptions_Run_RotateOutputIdentifiesIntentWithoutValues(t *testing.T) {
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}

	dir := setupSyncRepoWithSecrets(t, map[string]string{"ALPHA": "secret-alpha"})
	withDotenvTarget(t, dir, "out.env", false)

	jsonOut := runSyncCmd(t, dir, []string{"--rotate", "--format", "json"})
	var results []SyncResult
	require.NoError(t, json.Unmarshal([]byte(jsonOut), &results))
	require.Len(t, results, 1)
	assert.Equal(t, "rotate", results[0].Intent)
	assert.NotContains(t, jsonOut, "secret-alpha")

	tableOut := runSyncCmd(t, dir, []string{"--rotate"})
	assert.Contains(t, tableOut, "Rotated 1 secrets to dotenv")
	assert.NotContains(t, tableOut, "secret-alpha")

	_, err := os.Stat(filepath.Join(dir, "out.env"))
	require.NoError(t, err)
}
