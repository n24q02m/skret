package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/syncer"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSync_PerKeyTargetJournalsPartialFailureWithoutFalseSuccess(t *testing.T) {
	var mu sync.Mutex
	var names []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		var payload map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		mu.Lock()
		names = append(names, payload["name"])
		mu.Unlock()
		if payload["name"] == "B" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":[{"message":"opaque provider failure"}]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(fmt.Sprintf(`version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
sync:
  targets:
    - type: cloudflare
      account: account
      worker: worker
      base_url: %s
`, server.URL)), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte("version: \"1\"\nsecrets:\n  A: alpha\n  B: bravo\n  C: charlie\n"), 0o600))

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("CLOUDFLARE_API_TOKEN", "token")

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"sync", "--skip-unchanged", "--format=json"})
	err = cmd.Execute()
	require.Error(t, err)
	assert.Equal(t, skret.ExitNetworkError, skret.ExitCode(err))
	assert.Empty(t, stdout.String(), "a failed durable operation must not emit global success")
	assert.NotContains(t, stderr.String(), "alpha")
	assert.NotContains(t, stderr.String(), "bravo")
	assert.NotContains(t, stderr.String(), "charlie")

	mu.Lock()
	gotNames := append([]string(nil), names...)
	mu.Unlock()
	assert.Equal(t, []string{"A", "B"}, gotNames, "failed key stops the one-key operation before unattempted keys")

	state, err := syncer.LoadSyncState("cloudflare", "worker/worker")
	require.NoError(t, err)
	assert.Equal(t, syncer.OperationPhaseNeedsReconciliation, state.Phase)
	assert.Equal(t, syncer.OutcomeSucceeded, state.Outcomes["A"].Status)
	assert.Equal(t, syncer.OutcomeNeedsReconciliation, state.Outcomes["B"].Status)
	assert.Equal(t, syncer.OutcomePending, state.Outcomes["C"].Status)
	assert.Equal(t, sha256Hex("alpha"), state.Hashes["A"])
	assert.NotContains(t, state.Hashes, "B")
	assert.NotContains(t, state.Hashes, "C")
	assert.NotEqual(t, syncer.OperationPhaseSucceeded, state.Phase)
}

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func TestSync_PerKeyRecoversPendingOperationAfterFinalJournalSaveFailure(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(fmt.Sprintf(`version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
sync:
  targets:
    - type: cloudflare
      account: account
      worker: worker
      base_url: %s
`, server.URL)), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte("version: \"1\"\nsecrets:\n  A: alpha\n  B: bravo\n"), 0o600))

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("CLOUDFLARE_API_TOKEN", "token")

	started := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	state := &syncer.SyncState{
		Target:      "cloudflare",
		ID:          "worker/worker",
		OperationID: "op-final-save",
		Phase:       syncer.OperationPhasePending,
		StartedAt:   &started,
		Hashes: map[string]string{
			"A": sha256Hex("alpha"),
			"B": sha256Hex("bravo"),
		},
		Outcomes: map[string]syncer.KeyOutcome{
			"A": {Status: syncer.OutcomeSucceeded, OperationID: "op-final-save", UpdatedAt: started},
			"B": {Status: syncer.OutcomeSucceeded, OperationID: "op-final-save", UpdatedAt: started},
		},
	}
	require.NoError(t, syncer.SaveSyncState(state))

	var stdout bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"sync", "--skip-unchanged", "--format=json"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, stdout.String(), `"synced": 0`)
	assert.Equal(t, 0, requests, "recovery must not rewrite already acknowledged keys")

	recovered, err := syncer.LoadSyncState("cloudflare", "worker/worker")
	require.NoError(t, err)
	assert.Equal(t, syncer.OperationPhaseSucceeded, recovered.Phase)
	assert.NotNil(t, recovered.CompletedAt)
	assert.NotNil(t, recovered.LastSuccess)
}

func TestSync_PerKeyJournalFailureIsGenericAndValueFree(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(fmt.Sprintf(`version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
sync:
  targets:
    - type: cloudflare
      account: account
      worker: worker
      base_url: %s
`, server.URL)), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte("version: \"1\"\nsecrets:\n  A: alpha\n  B: bravo\n"), 0o600))

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("CLOUDFLARE_API_TOKEN", "token")

	originalSave := saveSyncState
	defer func() { saveSyncState = originalSave }()
	var saveCalls int
	saveSyncState = func(state *syncer.SyncState) error {
		saveCalls++
		if saveCalls == 3 {
			return errors.New("opaque journal failure")
		}
		return syncer.SaveSyncState(state)
	}

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"sync", "--skip-unchanged", "--format=json"})
	err = cmd.Execute()
	require.Error(t, err)
	assert.Equal(t, skret.ExitGenericError, skret.ExitCode(err))
	assert.Empty(t, stdout.String())
	assert.NotContains(t, err.Error(), "alpha")
	assert.NotContains(t, err.Error(), "bravo")
	assert.Equal(t, 2, requests, "provider acknowledgements happen before the final journal save")

	state, err := syncer.LoadSyncState("cloudflare", "worker/worker")
	require.NoError(t, err)
	assert.Equal(t, syncer.OperationPhasePending, state.Phase)
	assert.Equal(t, syncer.OutcomeSucceeded, state.Outcomes["A"].Status)
	assert.Equal(t, syncer.OutcomeSucceeded, state.Outcomes["B"].Status)
	assert.Equal(t, sha256Hex("alpha"), state.Hashes["A"])
	assert.Equal(t, sha256Hex("bravo"), state.Hashes["B"])
	assert.Nil(t, state.CompletedAt)
	assert.Nil(t, state.LastSuccess)
}
