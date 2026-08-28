package syncer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withFakeHome redirects os.UserHomeDir() to t.TempDir() for the duration of
// a test so SaveSyncState / LoadSyncState write to an isolated location.
func withFakeHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	} else {
		t.Setenv("HOME", dir)
	}
	return dir
}

func TestStatePathFor_EncodesIDWithoutPathSyntax(t *testing.T) {
	ids := []string{"n24q02m/skret", "github:owner:repo", "my file path", `windows\path`}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			withFakeHome(t)
			path, err := StatePathFor("github", id)
			require.NoError(t, err)
			base := filepath.Base(path)
			assert.True(t, strings.HasPrefix(base, "v1-"))
			assert.True(t, strings.HasSuffix(base, ".json"))
			assert.NotContains(t, base, string(filepath.Separator))
			assert.NotContains(t, base, "..")
		})
	}
}

func TestLoadSyncState_FirstRun_ReturnsEmpty(t *testing.T) {
	withFakeHome(t)
	state, err := LoadSyncState("github", "owner/repo")
	require.NoError(t, err)
	assert.Equal(t, "github", state.Target)
	assert.Equal(t, "owner/repo", state.ID)
	assert.NotNil(t, state.Hashes)
	assert.Empty(t, state.Hashes)
}

func TestSaveAndLoadSyncState_Roundtrip(t *testing.T) {
	home := withFakeHome(t)
	state, err := LoadSyncState("github", "owner/repo")
	require.NoError(t, err)

	state.Update([]*provider.Secret{
		{Key: "/myapp/prod/DB_URL", Value: "postgres://example"},
		{Key: "/myapp/prod/API_KEY", Value: "sk-abc"},
	})
	require.NoError(t, SaveSyncState(state))

	// Verify file written under fake home with 0600 permissions on POSIX
	path, err := StatePathFor("github", "owner/repo")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(path, home))

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	loaded, err := LoadSyncState("github", "owner/repo")
	require.NoError(t, err)
	assert.Len(t, loaded.Hashes, 2)
	assert.Equal(t, hashSecret("postgres://example"), loaded.Hashes["/myapp/prod/DB_URL"])
	assert.Equal(t, hashSecret("sk-abc"), loaded.Hashes["/myapp/prod/API_KEY"])
	assert.False(t, loaded.Updated.IsZero())
}

func TestFilterUnchanged_NewSecretIncluded(t *testing.T) {
	state := &SyncState{Hashes: map[string]string{}}
	secrets := []*provider.Secret{
		{Key: "K1", Value: "v1"},
		{Key: "K2", Value: "v2"},
	}
	out := state.FilterUnchanged(secrets)
	assert.Equal(t, secrets, out)
}

func TestFilterUnchanged_UnchangedExcluded(t *testing.T) {
	state := &SyncState{Hashes: map[string]string{
		"K1": hashSecret("v1"),
	}}
	secrets := []*provider.Secret{
		{Key: "K1", Value: "v1"}, // unchanged → excluded
		{Key: "K2", Value: "v2"}, // new → included
	}
	out := state.FilterUnchanged(secrets)
	require.Len(t, out, 1)
	assert.Equal(t, "K2", out[0].Key)
}

func TestFilterUnchanged_ChangedIncluded(t *testing.T) {
	state := &SyncState{Hashes: map[string]string{
		"K1": hashSecret("old-value"),
	}}
	secrets := []*provider.Secret{
		{Key: "K1", Value: "new-value"}, // hash differs → included
	}
	out := state.FilterUnchanged(secrets)
	require.Len(t, out, 1)
	assert.Equal(t, "K1", out[0].Key)
}

func TestUpdate_PopulatesHashes(t *testing.T) {
	state := &SyncState{}
	state.Update([]*provider.Secret{
		{Key: "K", Value: "v"},
	})
	require.NotNil(t, state.Hashes)
	assert.Equal(t, hashSecret("v"), state.Hashes["K"])
}

func TestSaveSyncState_CreatesDirWithSecureMode(t *testing.T) {
	home := withFakeHome(t)
	state := &SyncState{Target: "github", ID: "owner/repo", Hashes: map[string]string{}}
	require.NoError(t, SaveSyncState(state))

	dir := filepath.Join(home, ".skret", "sync-state")
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	}
}

func TestLoadSyncState_CorruptFile_ReturnsError(t *testing.T) {
	home := withFakeHome(t)
	dir := filepath.Join(home, ".skret", "sync-state")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	path, err := StatePathFor("github", "owner/repo")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("not json {"), 0o600))

	_, err = LoadSyncState("github", "owner/repo")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse sync state")
}

func TestHashSecret_Stable(t *testing.T) {
	a := hashSecret("hello")
	b := hashSecret("hello")
	c := hashSecret("hello!")
	assert.Equal(t, a, b)
	assert.NotEqual(t, a, c)
	assert.Len(t, a, 64) // sha256 hex = 64 chars
}

func TestStatePathFor_NoHomeDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", "")
		t.Setenv("HOMEDRIVE", "")
		t.Setenv("HOMEPATH", "")
	} else {
		t.Setenv("HOME", "")
	}
	_, err := StatePathFor("github", "owner/repo")
	if err == nil {
		t.Skip("UserHomeDir did not error in this environment; nothing to assert")
	}
	assert.Contains(t, err.Error(), "user home dir")
}

func TestSaveSyncState_UpdatedTimeStamp(t *testing.T) {
	withFakeHome(t)
	state := &SyncState{Target: "github", ID: "owner/repo", Hashes: map[string]string{"K": hashSecret("v")}}
	require.NoError(t, SaveSyncState(state))
	first := state.Updated
	assert.False(t, first.IsZero())

	// Roundtrip preserves Updated; second SaveSyncState advances it.
	require.NoError(t, SaveSyncState(state))
	assert.False(t, state.Updated.Before(first))
}

func TestSaveSyncState_Atomic(t *testing.T) {
	home := withFakeHome(t)
	state := &SyncState{Target: "github", ID: "owner/repo", Hashes: map[string]string{"K": hashSecret("v")}}
	require.NoError(t, SaveSyncState(state))

	path, err := StatePathFor("github", "owner/repo")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(path, home))

	// .tmp file should not survive a successful SaveSyncState.
	_, statErr := os.Stat(path + ".tmp")
	assert.True(t, errors.Is(statErr, os.ErrNotExist))
}

func TestSaveSyncState_ConcurrentSaves(t *testing.T) {
	withFakeHome(t)
	const saves = 64

	start := make(chan struct{})
	errs := make(chan error, saves)
	var wg sync.WaitGroup
	for range saves {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			state := &SyncState{
				Target: "github",
				ID:     "owner/repo",
				Hashes: map[string]string{"K": hashSecret("value")},
			}
			errs <- SaveSyncState(state)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	path, err := StatePathFor("github", "owner/repo")
	require.NoError(t, err)
	loaded, err := LoadSyncState("github", "owner/repo")
	require.NoError(t, err)
	assert.Equal(t, hashSecret("value"), loaded.Hashes["K"])

	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	for _, entry := range entries {
		assert.NotContains(t, entry.Name(), ".tmp", "temporary artifact survived: %s", entry.Name())
	}
}

func TestSaveSyncState_RenameFailureCleansTemp(t *testing.T) {
	withFakeHome(t)
	state := &SyncState{
		Target: "github",
		ID:     "owner/repo",
		Hashes: map[string]string{"K": hashSecret("value")},
	}
	path, err := StatePathFor(state.Target, state.ID)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.Mkdir(path, 0o700))

	err = SaveSyncState(state)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "value")

	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, filepath.Base(path), entries[0].Name())
	assert.True(t, entries[0].IsDir())
}

// TestStatePathFor_BlocksPathTraversal verifies neither target nor id can
// escape the ~/.skret/sync-state directory. This guards a HIGH severity
// path-traversal class of bugs where untrusted input (target/id) could
// otherwise be written outside the intended directory.
func TestStatePathFor_BlocksPathTraversal(t *testing.T) {
	cases := []struct {
		name   string
		target string
		id     string
	}{
		{"dotdot in id", "github", "../../etc/passwd"},
		{"dotdot in target", "../../etc", "owner-repo"},
		{"slash separator", "gh", "a/b/c/d"},
		{"backslash separator", "gh", `a\b\c`},
		{"null byte", "gh", "id\x00x"},
		{"only dots", "gh", ".."},
		{"empty id", "gh", ""},
		{"single dot", "gh", "."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := withFakeHome(t)
			path, err := StatePathFor(tc.target, tc.id)
			require.NoError(t, err)
			expectedDir := filepath.Join(home, ".skret", "sync-state")
			assert.True(t, strings.HasPrefix(path, expectedDir+string(filepath.Separator)),
				"path %q must live inside %q", path, expectedDir)
			rel, err := filepath.Rel(expectedDir, path)
			require.NoError(t, err)
			assert.NotContains(t, rel, "..", "rel %q must not contain ..", rel)
			assert.NotContains(t, rel, string(filepath.Separator),
				"sanitized filename must not include separators (got %q)", rel)
		})
	}
}

func TestStatePathFor_PathTraversalEncoding(t *testing.T) {
	home := withFakeHome(t)
	path, err := StatePathFor("target", "../../../etc/passwd")
	require.NoError(t, err)
	rel, err := filepath.Rel(filepath.Join(home, ".skret", "sync-state"), path)
	require.NoError(t, err)
	assert.NotContains(t, rel, "..")
	assert.NotContains(t, rel, string(filepath.Separator))
	assert.True(t, strings.HasPrefix(filepath.Base(path), "v1-"))
}

// TestSaveSyncState_PathTraversal verifies that even with a malicious id the
// file is written inside the sync-state directory and the attacker cannot land
// a file in a sibling directory.
func TestSaveSyncState_PathTraversal(t *testing.T) {
	home := withFakeHome(t)
	state := &SyncState{
		Target: "../../../evil-target",
		ID:     "../../etc/passwd",
		Hashes: map[string]string{"K": hashSecret("v")},
	}
	require.NoError(t, SaveSyncState(state))

	_, err := os.Stat(filepath.Join(home, ".skret", "evil-target"))
	assert.True(t, errors.Is(err, os.ErrNotExist), "no escape above sync-state")

	stateDir := filepath.Join(home, ".skret", "sync-state")
	entries, err := os.ReadDir(stateDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.True(t, strings.HasSuffix(entries[0].Name(), ".json"))
	assert.NotContains(t, entries[0].Name(), "..")
}

func TestSyncState_OperationSuccessRecordsLifecycle(t *testing.T) {
	started := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)
	finished := started.Add(2 * time.Second)
	secrets := []*provider.Secret{
		{Key: "K1", Value: "v1"},
		{Key: "K2", Value: "v2"},
	}
	state := &SyncState{Target: "dotenv", ID: ".env"}

	require.NoError(t, state.BeginOperation("op-1", secrets, started))
	assert.Equal(t, OutcomePending, state.Outcomes["K1"].Status)
	assert.Equal(t, OutcomePending, state.Outcomes["K2"].Status)

	require.NoError(t, state.RecordSuccess("op-1", secrets, finished))
	assert.Equal(t, "op-1", state.OperationID)
	require.NotNil(t, state.StartedAt)
	require.NotNil(t, state.CompletedAt)
	require.NotNil(t, state.LastSuccess)
	assert.Equal(t, started, *state.StartedAt)
	assert.Equal(t, finished, *state.CompletedAt)
	assert.Equal(t, finished, *state.LastSuccess)
	assert.Equal(t, OutcomeSucceeded, state.Outcomes["K1"].Status)
	assert.Equal(t, hashSecret("v1"), state.Hashes["K1"])
}

func TestSyncState_OperationFailureNeedsReconciliation(t *testing.T) {
	now := time.Date(2026, 8, 22, 9, 5, 0, 0, time.UTC)
	secrets := []*provider.Secret{{Key: "K1", Value: "v1"}}
	state := &SyncState{Target: "github", ID: "o/r"}

	require.NoError(t, state.BeginOperation("op-2", secrets, now))
	require.NoError(t, state.RecordNeedsReconciliation("op-2", secrets, now.Add(time.Second)))

	assert.Equal(t, OutcomeNeedsReconciliation, state.Outcomes["K1"].Status)
	assert.Equal(t, OperationPhaseNeedsReconciliation, state.Phase)
	assert.Equal(t, "op-2", state.Outcomes["K1"].OperationID)
	assert.Empty(t, state.Hashes)
	assert.Nil(t, state.LastSuccess)
	require.NotNil(t, state.CompletedAt)
	assert.Equal(t, now.Add(time.Second), *state.CompletedAt)
}

func TestSyncState_RejectsStaleOperationResult(t *testing.T) {
	now := time.Date(2026, 8, 22, 9, 10, 0, 0, time.UTC)
	secrets := []*provider.Secret{{Key: "K1", Value: "v1"}}
	state := &SyncState{Target: "cloudflare", ID: "worker/w"}

	require.NoError(t, state.BeginOperation("op-current", secrets, now))
	err := state.RecordSuccess("op-stale", secrets, now.Add(time.Second))
	require.ErrorIs(t, err, ErrOperationMismatch)
	assert.Equal(t, OperationPhasePending, state.Phase)
	assert.Equal(t, OutcomePending, state.Outcomes["K1"].Status)
	assert.Equal(t, "op-current", state.Outcomes["K1"].OperationID)
	assert.Empty(t, state.Hashes)
}

func TestSyncState_BeginOperationSupersedesInterruptedOperation(t *testing.T) {
	first := time.Date(2026, 8, 22, 9, 15, 0, 0, time.UTC)
	second := first.Add(time.Minute)
	secrets := []*provider.Secret{{Key: "K1", Value: "v1"}}
	state := &SyncState{Target: "dotenv", ID: ".env"}

	require.NoError(t, state.BeginOperation("op-interrupted", secrets, first))
	require.NoError(t, state.BeginOperation("op-retry", secrets, second))

	assert.Equal(t, "op-retry", state.OperationID)
	require.NotNil(t, state.StartedAt)
	assert.Equal(t, second, *state.StartedAt)
	assert.Equal(t, OutcomePending, state.Outcomes["K1"].Status)
}

func TestSyncState_OperationPhaseAndOwnership(t *testing.T) {
	started := time.Date(2026, 8, 23, 9, 0, 0, 0, time.UTC)
	finished := started.Add(time.Second)
	secrets := []*provider.Secret{{Key: "K1", Value: "v1"}}
	state := &SyncState{Target: "dotenv", ID: ".env"}

	require.NoError(t, state.BeginOperation("op-1", secrets, started))
	assert.Equal(t, OperationPhasePending, state.Phase)
	assert.Equal(t, "op-1", state.Outcomes["K1"].OperationID)

	require.NoError(t, state.RecordSuccess("op-1", secrets, finished))
	assert.Equal(t, OperationPhaseSucceeded, state.Phase)
	assert.Equal(t, "op-1", state.Outcomes["K1"].OperationID)
}

func TestSyncState_InterruptedPendingOutcomesRetainOwnership(t *testing.T) {
	first := time.Date(2026, 8, 23, 9, 5, 0, 0, time.UTC)
	second := first.Add(time.Minute)
	secrets := []*provider.Secret{
		{Key: "K1", Value: "v1"},
		{Key: "K2", Value: "v2"},
	}
	state := &SyncState{Target: "dotenv", ID: ".env"}

	require.NoError(t, state.BeginOperation("op-first", secrets, first))
	require.NoError(t, state.BeginOperation("op-second", secrets[1:], second))

	assert.Equal(t, OperationPhasePending, state.Phase)
	assert.Equal(t, OutcomeNeedsReconciliation, state.Outcomes["K1"].Status)
	assert.Equal(t, "op-first", state.Outcomes["K1"].OperationID)
	assert.Equal(t, OutcomePending, state.Outcomes["K2"].Status)
	assert.Equal(t, "op-second", state.Outcomes["K2"].OperationID)
}

func TestSyncState_RecordOnlyUpdatesCurrentKeyOwnership(t *testing.T) {
	now := time.Date(2026, 8, 23, 9, 10, 0, 0, time.UTC)
	state := &SyncState{Target: "dotenv", ID: ".env"}
	current := []*provider.Secret{{Key: "current", Value: "current"}}
	stale := &provider.Secret{Key: "stale", Value: "stale"}

	require.NoError(t, state.BeginOperation("op-current", current, now))
	state.Outcomes["stale"] = KeyOutcome{
		Status:      OutcomePending,
		OperationID: "op-old",
		UpdatedAt:   now,
	}

	err := state.RecordSuccess("op-current", []*provider.Secret{current[0], stale}, now.Add(time.Second))
	require.ErrorIs(t, err, ErrOperationKeyMismatch)

	assert.Equal(t, OutcomePending, state.Outcomes["current"].Status)
	assert.Equal(t, "op-current", state.Outcomes["current"].OperationID)
	assert.Equal(t, OutcomePending, state.Outcomes["stale"].Status)
	assert.Equal(t, "op-old", state.Outcomes["stale"].OperationID)
	assert.Empty(t, state.Hashes)
}

func TestSyncState_OperationMetadataRoundtripAndLegacyJSON(t *testing.T) {
	withFakeHome(t)
	started := time.Date(2026, 8, 23, 9, 15, 0, 0, time.UTC)
	state := &SyncState{Target: "dotenv", ID: ".env"}
	secrets := []*provider.Secret{{Key: "K1", Value: "v1"}}
	require.NoError(t, state.BeginOperationWithIntent("op-rotate", OperationIntentRotate, secrets, started))
	require.NoError(t, SaveSyncState(state))

	loaded, err := LoadSyncState("dotenv", ".env")
	require.NoError(t, err)
	assert.Equal(t, OperationPhasePending, loaded.Phase)
	assert.Equal(t, OperationIntentRotate, loaded.Intent)
	assert.Equal(t, "op-rotate", loaded.Outcomes["K1"].OperationID)
	path, err := StatePathFor("dotenv", ".env")
	require.NoError(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "v1")

	path, err = StatePathFor("github", "owner/repo")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(`{"target":"github","id":"owner/repo","hashes":{},"outcomes":{"K1":{"status":"succeeded","updated_at":"2026-08-23T09:15:00Z"}}}`), 0o600))

	legacy, err := LoadSyncState("github", "owner/repo")
	require.NoError(t, err)
	assert.Empty(t, legacy.Phase)
	assert.Empty(t, legacy.Outcomes["K1"].OperationID)
}

func TestSyncState_RecordKeySuccess_PartialRemainsPending(t *testing.T) {
	started := time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)
	completed := started.Add(time.Second)
	secrets := []*provider.Secret{
		{Key: "K1", Value: "v1"},
		{Key: "K2", Value: "v2"},
	}
	state := &SyncState{Target: "dotenv", ID: ".env"}

	require.NoError(t, state.BeginOperation("op-partial", secrets, started))
	require.NoError(t, state.RecordKeySuccess("op-partial", secrets[0], completed))

	assert.Equal(t, OutcomeSucceeded, state.Outcomes["K1"].Status)
	assert.Equal(t, OutcomePending, state.Outcomes["K2"].Status)
	assert.Equal(t, OperationPhasePending, state.Phase)
	assert.Nil(t, state.CompletedAt)
	assert.Nil(t, state.LastSuccess)
	assert.Equal(t, hashSecret("v1"), state.Hashes["K1"])
	assert.NotContains(t, state.Hashes, "K2")
}

func TestSyncState_RecordKeyNeedsReconciliation_PartialSetsPhase(t *testing.T) {
	started := time.Date(2026, 8, 23, 10, 5, 0, 0, time.UTC)
	completed := started.Add(time.Second)
	secrets := []*provider.Secret{
		{Key: "K1", Value: "v1"},
		{Key: "K2", Value: "v2"},
	}
	state := &SyncState{Target: "dotenv", ID: ".env"}

	require.NoError(t, state.BeginOperation("op-reconcile", secrets, started))
	require.NoError(t, state.RecordKeySuccess("op-reconcile", secrets[0], completed))
	require.NoError(t, state.RecordKeyNeedsReconciliation("op-reconcile", secrets[1], completed))

	assert.Equal(t, OutcomeSucceeded, state.Outcomes["K1"].Status)
	assert.Equal(t, OutcomeNeedsReconciliation, state.Outcomes["K2"].Status)
	assert.Equal(t, OperationPhaseNeedsReconciliation, state.Phase)
	assert.Nil(t, state.LastSuccess)
	assert.Equal(t, hashSecret("v1"), state.Hashes["K1"])
	assert.NotContains(t, state.Hashes, "K2")
}

func TestSyncState_FinalizeOperation_WaitsForAllAcks(t *testing.T) {
	started := time.Date(2026, 8, 23, 10, 10, 0, 0, time.UTC)
	firstAck := started.Add(time.Second)
	finalized := started.Add(2 * time.Second)
	secrets := []*provider.Secret{
		{Key: "K1", Value: "v1"},
		{Key: "K2", Value: "v2"},
	}
	state := &SyncState{Target: "dotenv", ID: ".env"}

	require.NoError(t, state.BeginOperation("op-finalize", secrets, started))
	require.NoError(t, state.RecordKeySuccess("op-finalize", secrets[0], firstAck))
	require.NoError(t, state.FinalizeOperation("op-finalize", finalized))

	assert.Equal(t, OperationPhasePending, state.Phase)
	assert.Nil(t, state.CompletedAt)
	assert.Nil(t, state.LastSuccess)
	assert.Equal(t, OutcomeSucceeded, state.Outcomes["K1"].Status)
	assert.Equal(t, OutcomePending, state.Outcomes["K2"].Status)
	assert.NotContains(t, state.Hashes, "K2")

	require.NoError(t, state.RecordKeySuccess("op-finalize", secrets[1], finalized))
	require.NoError(t, state.FinalizeOperation("op-finalize", finalized))

	assert.Equal(t, OperationPhaseSucceeded, state.Phase)
	require.NotNil(t, state.CompletedAt)
	require.NotNil(t, state.LastSuccess)
	assert.Equal(t, finalized, *state.CompletedAt)
	assert.Equal(t, finalized, *state.LastSuccess)
	assert.Equal(t, hashSecret("v2"), state.Hashes["K2"])
}

func TestSyncState_FinalizeOperation_RetainsReconciliation(t *testing.T) {
	started := time.Date(2026, 8, 23, 10, 15, 0, 0, time.UTC)
	ack := started.Add(time.Second)
	finalized := started.Add(2 * time.Second)
	secrets := []*provider.Secret{
		{Key: "K1", Value: "v1"},
		{Key: "K2", Value: "v2"},
	}
	state := &SyncState{Target: "dotenv", ID: ".env"}

	require.NoError(t, state.BeginOperation("op-reconcile-final", secrets, started))
	require.NoError(t, state.RecordKeySuccess("op-reconcile-final", secrets[0], ack))
	require.NoError(t, state.RecordKeyNeedsReconciliation("op-reconcile-final", secrets[1], ack))
	require.NoError(t, state.FinalizeOperation("op-reconcile-final", finalized))

	assert.Equal(t, OperationPhaseNeedsReconciliation, state.Phase)
	assert.Equal(t, OutcomeSucceeded, state.Outcomes["K1"].Status)
	assert.Equal(t, OutcomeNeedsReconciliation, state.Outcomes["K2"].Status)
	assert.Nil(t, state.LastSuccess)
	assert.Equal(t, hashSecret("v1"), state.Hashes["K1"])
	assert.NotContains(t, state.Hashes, "K2")
}

func TestSyncState_RecordKeyRejectsStaleAndUnownedWithoutMutation(t *testing.T) {
	started := time.Date(2026, 8, 23, 10, 20, 0, 0, time.UTC)
	state := &SyncState{Target: "dotenv", ID: ".env"}
	require.NoError(t, state.BeginOperation("op-current", []*provider.Secret{{Key: "K1", Value: "v1"}}, started))
	state.Outcomes["old"] = KeyOutcome{
		Status:      OutcomePending,
		OperationID: "op-old",
		UpdatedAt:   started,
	}

	before, err := json.Marshal(state)
	require.NoError(t, err)

	err = state.RecordKeySuccess("op-stale", &provider.Secret{Key: "K1", Value: "v1"}, started.Add(time.Second))
	require.ErrorIs(t, err, ErrOperationMismatch)
	after, marshalErr := json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))

	err = state.RecordKeyNeedsReconciliation("op-current", &provider.Secret{Key: "old", Value: "old-value"}, started.Add(time.Second))
	require.Error(t, err)
	after, marshalErr = json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))

	err = state.RecordKeySuccess("op-current", &provider.Secret{Key: "missing", Value: "missing-value"}, started.Add(time.Second))
	require.Error(t, err)
	after, marshalErr = json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))
}

func TestSyncState_RecordBatchRejectsUnknownWithoutMutation(t *testing.T) {
	started := time.Date(2026, 8, 23, 10, 25, 0, 0, time.UTC)
	state := &SyncState{Target: "dotenv", ID: ".env"}
	require.NoError(t, state.BeginOperation("op-batch", []*provider.Secret{{Key: "K1", Value: "v1"}}, started))

	before, err := json.Marshal(state)
	require.NoError(t, err)
	err = state.RecordSuccess("op-batch", []*provider.Secret{
		{Key: "K1", Value: "v1"},
		{Key: "unknown", Value: "not-a-secret-value"},
	}, started.Add(time.Second))
	require.Error(t, err)
	after, marshalErr := json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))

	err = state.RecordNeedsReconciliation("op-batch", []*provider.Secret{
		{Key: "K1", Value: "v1"},
		{Key: "unknown", Value: "not-a-secret-value"},
	}, started.Add(time.Second))
	require.Error(t, err)
	after, marshalErr = json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))
}

func TestSyncState_RecordBatchRejectsNilWithoutMutation(t *testing.T) {
	started := time.Date(2026, 8, 23, 10, 30, 0, 0, time.UTC)
	state := &SyncState{Target: "dotenv", ID: ".env"}
	require.NoError(t, state.BeginOperation("op-nil", []*provider.Secret{{Key: "K1", Value: "v1"}}, started))

	before, err := json.Marshal(state)
	require.NoError(t, err)
	err = state.RecordSuccess("op-nil", []*provider.Secret{nil}, started.Add(time.Second))
	require.Error(t, err)
	after, marshalErr := json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))

	err = state.RecordNeedsReconciliation("op-nil", []*provider.Secret{nil}, started.Add(time.Second))
	require.Error(t, err)
	after, marshalErr = json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))
}

func TestSyncState_FinalizeOperationRejectsEmptyOperation(t *testing.T) {
	state := &SyncState{Target: "dotenv", ID: ".env", Hashes: map[string]string{}}
	before, err := json.Marshal(state)
	require.NoError(t, err)

	err = state.FinalizeOperation("op-empty", time.Date(2026, 8, 23, 10, 35, 0, 0, time.UTC))
	require.Error(t, err)
	after, marshalErr := json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))
}

func TestSyncState_RecordKeyRejectsNilOrBlankWithoutMutation(t *testing.T) {
	started := time.Date(2026, 8, 23, 10, 40, 0, 0, time.UTC)
	state := &SyncState{Target: "dotenv", ID: ".env"}
	require.NoError(t, state.BeginOperation("op-key-validation", []*provider.Secret{{Key: "K1", Value: "v1"}}, started))

	before, err := json.Marshal(state)
	require.NoError(t, err)
	err = state.RecordKeySuccess("op-key-validation", nil, started.Add(time.Second))
	require.Error(t, err)
	after, marshalErr := json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))

	err = state.RecordKeyNeedsReconciliation("op-key-validation", &provider.Secret{
		Key:   " ",
		Value: "not-a-secret-value",
	}, started.Add(time.Second))
	require.Error(t, err)
	after, marshalErr = json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))
}

func TestSyncState_FinalizeOperationIgnoresOtherOperationOutcomes(t *testing.T) {
	started := time.Date(2026, 8, 23, 10, 45, 0, 0, time.UTC)
	finished := started.Add(time.Second)
	current := &provider.Secret{Key: "current", Value: "current"}
	state := &SyncState{Target: "dotenv", ID: ".env"}
	require.NoError(t, state.BeginOperation("op-current", []*provider.Secret{current}, started))
	state.Outcomes["old"] = KeyOutcome{
		Status:      OutcomePending,
		OperationID: "op-old",
		UpdatedAt:   started,
	}

	require.NoError(t, state.RecordKeySuccess("op-current", current, finished))
	require.NoError(t, state.FinalizeOperation("op-current", finished))

	assert.Equal(t, OperationPhaseSucceeded, state.Phase)
	require.NotNil(t, state.LastSuccess)
	assert.Equal(t, finished, *state.LastSuccess)
	assert.Equal(t, OutcomePending, state.Outcomes["old"].Status)
	assert.Equal(t, "op-old", state.Outcomes["old"].OperationID)
}

func TestSyncState_BeginOperationReconcilesPendingAfterPartialFailure(t *testing.T) {
	first := time.Date(2026, 8, 23, 10, 50, 0, 0, time.UTC)
	second := first.Add(time.Minute)
	secrets := []*provider.Secret{
		{Key: "K1", Value: "v1"},
		{Key: "K2", Value: "v2"},
	}
	state := &SyncState{Target: "dotenv", ID: ".env"}

	require.NoError(t, state.BeginOperation("op-first", secrets, first))
	require.NoError(t, state.RecordKeyNeedsReconciliation("op-first", secrets[0], first.Add(time.Second)))
	require.NoError(t, state.BeginOperation("op-second", []*provider.Secret{secrets[1]}, second))

	assert.Equal(t, OutcomeNeedsReconciliation, state.Outcomes["K1"].Status)
	assert.Equal(t, "op-first", state.Outcomes["K1"].OperationID)
	assert.Equal(t, OutcomePending, state.Outcomes["K2"].Status)
	assert.Equal(t, "op-second", state.Outcomes["K2"].OperationID)
}

func TestSyncState_RepeatedKeySuccessIsIdempotent(t *testing.T) {
	started := time.Date(2026, 8, 23, 10, 55, 0, 0, time.UTC)
	firstAck := started.Add(time.Second)
	secondAck := started.Add(2 * time.Second)
	secret := &provider.Secret{Key: "K1", Value: "v1"}
	state := &SyncState{Target: "dotenv", ID: ".env"}

	require.NoError(t, state.BeginOperation("op-idempotent-success", []*provider.Secret{secret}, started))
	require.NoError(t, state.RecordKeySuccess("op-idempotent-success", secret, firstAck))
	before, err := json.Marshal(state)
	require.NoError(t, err)

	secret.Value = "v2"
	require.NoError(t, state.RecordKeySuccess("op-idempotent-success", secret, secondAck))
	after, marshalErr := json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))
}

func TestSyncState_RepeatedKeyNeedsReconciliationIsIdempotent(t *testing.T) {
	started := time.Date(2026, 8, 23, 11, 0, 0, 0, time.UTC)
	firstAck := started.Add(time.Second)
	secondAck := started.Add(2 * time.Second)
	secret := &provider.Secret{Key: "K1", Value: "v1"}
	state := &SyncState{Target: "dotenv", ID: ".env"}

	require.NoError(t, state.BeginOperation("op-idempotent-reconcile", []*provider.Secret{secret}, started))
	require.NoError(t, state.RecordKeyNeedsReconciliation("op-idempotent-reconcile", secret, firstAck))
	before, err := json.Marshal(state)
	require.NoError(t, err)

	secret.Value = "v2"
	require.NoError(t, state.RecordKeyNeedsReconciliation("op-idempotent-reconcile", secret, secondAck))
	after, marshalErr := json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))
}

func TestSyncState_RepeatedFinalizeSuccessIsIdempotent(t *testing.T) {
	started := time.Date(2026, 8, 23, 11, 5, 0, 0, time.UTC)
	ack := started.Add(time.Second)
	firstFinalize := started.Add(2 * time.Second)
	secondFinalize := started.Add(3 * time.Second)
	secret := &provider.Secret{Key: "K1", Value: "v1"}
	state := &SyncState{Target: "dotenv", ID: ".env"}

	require.NoError(t, state.BeginOperation("op-idempotent-finalize", []*provider.Secret{secret}, started))
	require.NoError(t, state.RecordKeySuccess("op-idempotent-finalize", secret, ack))
	require.NoError(t, state.FinalizeOperation("op-idempotent-finalize", firstFinalize))
	before, err := json.Marshal(state)
	require.NoError(t, err)

	require.NoError(t, state.FinalizeOperation("op-idempotent-finalize", secondFinalize))
	after, marshalErr := json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))
}

func TestSyncState_RepeatedFinalizeReconciliationRetainsState(t *testing.T) {
	started := time.Date(2026, 8, 23, 11, 10, 0, 0, time.UTC)
	ack := started.Add(time.Second)
	firstFinalize := started.Add(2 * time.Second)
	secondFinalize := started.Add(3 * time.Second)
	secret := &provider.Secret{Key: "K1", Value: "v1"}
	state := &SyncState{Target: "dotenv", ID: ".env"}

	require.NoError(t, state.BeginOperation("op-idempotent-finalize-reconcile", []*provider.Secret{secret}, started))
	require.NoError(t, state.RecordKeyNeedsReconciliation("op-idempotent-finalize-reconcile", secret, ack))
	require.NoError(t, state.FinalizeOperation("op-idempotent-finalize-reconcile", firstFinalize))
	before, err := json.Marshal(state)
	require.NoError(t, err)

	require.NoError(t, state.FinalizeOperation("op-idempotent-finalize-reconcile", secondFinalize))
	after, marshalErr := json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))
}

func TestSyncState_GenerationMetadataRetainedForPartialAcknowledgement(t *testing.T) {
	started := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	deadline := started.Add(10 * time.Minute)
	secrets := []*provider.Secret{
		{Key: "K1", Value: "first"},
		{Key: "K2", Value: "second"},
	}
	state := &SyncState{Target: "github", ID: "owner/repo"}
	metadata := testGenerationMetadata(provider.CapabilityNativeCAS, 7, 8, deadline)

	require.NoError(t, state.BeginOperationWithMetadata("op-generation-partial", metadata, secrets, started))
	require.NoError(t, state.RecordKeySuccess("op-generation-partial", secrets[0], started.Add(time.Second)))
	require.NoError(t, state.FinalizeOperation("op-generation-partial", started.Add(2*time.Second)))

	outcome := state.Outcomes["K1"]
	require.NotNil(t, outcome.Metadata)
	assert.Equal(t, uint64(7), outcome.Metadata.OldGeneration)
	assert.Equal(t, uint64(8), outcome.Metadata.CurrentGeneration)
	assert.Equal(t, uint64(9), outcome.Metadata.IntendedGeneration)
	assert.Equal(t, "source-generation-9", outcome.Metadata.LifecycleLabel)
	assert.Equal(t, "kms-envelope-ref-9", outcome.Metadata.KMSEnvelopeRef)
	assert.Equal(t, provider.CapabilityNativeCAS, outcome.Metadata.Capability)
	assert.Equal(t, deadline, *outcome.Metadata.Deadline)
	assert.Equal(t, 2, outcome.Metadata.Attempts)
	assert.Empty(t, state.Hashes)
	assert.Equal(t, OperationPhasePending, state.Phase)
	assert.Nil(t, state.LastSuccess)
}

func TestSyncState_GenerationPromotesOnlyAfterAcknowledgementsAndVerification(t *testing.T) {
	started := time.Date(2026, 8, 24, 9, 15, 0, 0, time.UTC)
	deadline := started.Add(10 * time.Minute)
	secrets := []*provider.Secret{
		{Key: "K1", Value: "first"},
		{Key: "K2", Value: "second"},
	}
	state := &SyncState{Target: "github", ID: "owner/repo"}
	metadata := testGenerationMetadata(provider.CapabilityEnforcedExclusive, 11, 12, deadline)

	require.NoError(t, state.BeginOperationWithMetadata("op-generation-all", metadata, secrets, started))
	require.NoError(t, state.RecordKeySuccess("op-generation-all", secrets[0], started.Add(time.Second)))
	require.NoError(t, state.RecordKeySuccess("op-generation-all", secrets[1], started.Add(2*time.Second)))
	require.NoError(t, state.FinalizeOperation("op-generation-all", started.Add(3*time.Second)))

	for _, key := range []string{"K1", "K2"} {
		outcome := state.Outcomes[key]
		require.NotNil(t, outcome.Metadata)
		assert.Equal(t, uint64(12), outcome.Metadata.CurrentGeneration)
		assert.Equal(t, uint64(13), outcome.Metadata.IntendedGeneration)
		assert.NotEmpty(t, outcome.Metadata.LifecycleLabel)
		assert.NotEmpty(t, outcome.Metadata.KMSEnvelopeRef)
		assert.Equal(t, VerificationStatePending, outcome.Metadata.CanaryState)
		assert.Equal(t, VerificationStatePending, outcome.Metadata.PostconditionState)
	}
	assert.Equal(t, OperationPhaseAwaitingVerification, state.Phase)
	assert.Empty(t, state.Hashes)
	assert.Nil(t, state.LastSuccess)

	verifiedAt := started.Add(4 * time.Second)
	require.NoError(t, state.RecordOperationVerification("op-generation-all", true, true, verifiedAt))
	for _, key := range []string{"K1", "K2"} {
		outcome := state.Outcomes[key]
		assert.Equal(t, uint64(13), outcome.Metadata.CurrentGeneration)
		assert.Zero(t, outcome.Metadata.OldGeneration)
		assert.Empty(t, outcome.Metadata.LifecycleLabel)
		assert.Empty(t, outcome.Metadata.KMSEnvelopeRef)
		assert.Equal(t, VerificationStatePassed, outcome.Metadata.CanaryState)
		assert.Equal(t, VerificationStatePassed, outcome.Metadata.PostconditionState)
	}
	assert.Equal(t, OperationPhaseSucceeded, state.Phase)
	require.NotNil(t, state.LastSuccess)
	assert.Equal(t, hashSecret("first"), state.Hashes["K1"])
	assert.Equal(t, hashSecret("second"), state.Hashes["K2"])
	assert.Equal(t, verifiedAt, *state.LastSuccess)
}

func TestSyncState_BlockedCapabilityCannotFinalizeSuccess(t *testing.T) {
	started := time.Date(2026, 8, 24, 9, 30, 0, 0, time.UTC)
	secret := &provider.Secret{Key: "K1", Value: "first"}
	state := &SyncState{Target: "github", ID: "owner/repo"}
	metadata := testGenerationMetadata(provider.CapabilityBlocked, 3, 4, started.Add(5*time.Minute))

	require.NoError(t, state.BeginOperationWithMetadata("op-generation-blocked", metadata, []*provider.Secret{secret}, started))
	err := state.RecordKeySuccess("op-generation-blocked", secret, started.Add(time.Second))

	require.ErrorIs(t, err, ErrOperationCapabilityBlocked)
	assert.Equal(t, OutcomeNeedsReconciliation, state.Outcomes["K1"].Status)
	assert.Equal(t, OperationPhaseNeedsReconciliation, state.Phase)
	assert.Empty(t, state.Hashes)
	require.NotNil(t, state.Outcomes["K1"].Metadata)
	assert.Equal(t, ReconciliationStatePending, state.Outcomes["K1"].Metadata.ReconciliationState)
	require.NoError(t, state.FinalizeOperation("op-generation-blocked", started.Add(2*time.Second)))
	assert.Equal(t, OperationPhaseNeedsReconciliation, state.Phase)
	assert.Nil(t, state.LastSuccess)
}

func TestSyncState_OwnerRiskCapabilityRequiresReconciliationApproval(t *testing.T) {
	started := time.Date(2026, 8, 24, 9, 45, 0, 0, time.UTC)
	secret := &provider.Secret{Key: "K1", Value: "first"}
	state := &SyncState{Target: "github", ID: "owner/repo"}
	metadata := testGenerationMetadata(provider.CapabilityOwnerRiskGate, 20, 21, started.Add(5*time.Minute))

	require.NoError(t, state.BeginOperationWithMetadata("op-generation-owner-risk", metadata, []*provider.Secret{secret}, started))
	err := state.RecordKeySuccess("op-generation-owner-risk", secret, started.Add(time.Second))
	require.ErrorIs(t, err, ErrOperationOwnerRiskApprovalRequired)
	assert.Equal(t, OutcomeNeedsReconciliation, state.Outcomes["K1"].Status)
	require.NotNil(t, state.Outcomes["K1"].Metadata)
	assert.Equal(t, ReconciliationStateOwnerRiskRequired, state.Outcomes["K1"].Metadata.ReconciliationState)
	assert.Empty(t, state.Hashes)

	require.NoError(t, state.ApproveOwnerRiskReconciliation("op-generation-owner-risk", "K1", started.Add(2*time.Second)))
	assert.Equal(t, ReconciliationStateApproved, state.Outcomes["K1"].Metadata.ReconciliationState)
	require.NoError(t, state.RecordKeySuccess("op-generation-owner-risk", secret, started.Add(3*time.Second)))
	require.NoError(t, state.FinalizeOperation("op-generation-owner-risk", started.Add(4*time.Second)))
	assert.Equal(t, OperationPhaseAwaitingVerification, state.Phase)
	require.NoError(t, state.RecordOperationVerification("op-generation-owner-risk", true, true, started.Add(5*time.Second)))
	assert.Equal(t, OperationPhaseSucceeded, state.Phase)
	assert.Equal(t, uint64(22), state.Outcomes["K1"].Metadata.CurrentGeneration)
}

func TestSyncState_GenerationOperationRejectsStaleOperationIDWithoutMutation(t *testing.T) {
	started := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	secret := &provider.Secret{Key: "K1", Value: "first"}
	state := &SyncState{Target: "github", ID: "owner/repo"}
	metadata := testGenerationMetadata(provider.CapabilityNativeCAS, 30, 31, started.Add(5*time.Minute))
	require.NoError(t, state.BeginOperationWithMetadata("op-generation-current", metadata, []*provider.Secret{secret}, started))

	before, err := json.Marshal(state)
	require.NoError(t, err)
	err = state.RecordKeySuccess("op-generation-stale", secret, started.Add(time.Second))
	require.ErrorIs(t, err, ErrOperationMismatch)
	after, marshalErr := json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))
	assert.Equal(t, OutcomePending, state.Outcomes["K1"].Status)
	assert.Empty(t, state.Hashes)
}

func TestSyncState_GenerationTerminalFinalizeIsIdempotent(t *testing.T) {
	started := time.Date(2026, 8, 24, 10, 15, 0, 0, time.UTC)
	secret := &provider.Secret{Key: "K1", Value: "first"}
	state := &SyncState{Target: "github", ID: "owner/repo"}
	metadata := testGenerationMetadata(provider.CapabilityNativeCAS, 40, 41, started.Add(5*time.Minute))
	require.NoError(t, state.BeginOperationWithMetadata("op-generation-terminal", metadata, []*provider.Secret{secret}, started))
	require.NoError(t, state.RecordKeySuccess("op-generation-terminal", secret, started.Add(time.Second)))
	require.NoError(t, state.FinalizeOperation("op-generation-terminal", started.Add(2*time.Second)))
	require.NoError(t, state.RecordOperationVerification("op-generation-terminal", true, true, started.Add(3*time.Second)))

	before, err := json.Marshal(state)
	require.NoError(t, err)
	require.NoError(t, state.FinalizeOperation("op-generation-terminal", started.Add(4*time.Second)))
	after, marshalErr := json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))
	assert.Equal(t, OperationPhaseSucceeded, state.Phase)
	assert.Equal(t, uint64(42), state.Outcomes["K1"].Metadata.CurrentGeneration)
}

func TestSyncState_VerificationFailureRetainsGenerationAndBlocksSuccessor(t *testing.T) {
	started := time.Date(2026, 8, 24, 10, 30, 0, 0, time.UTC)
	secret := &provider.Secret{Key: "K1", Value: "first"}
	state := &SyncState{Target: "github", ID: "owner/repo"}
	metadata := testGenerationMetadata(provider.CapabilityNativeCAS, 50, 51, started.Add(5*time.Minute))

	require.NoError(t, state.BeginOperationWithMetadata("op-verification-fails", metadata, []*provider.Secret{secret}, started))
	require.NoError(t, state.RecordKeySuccess("op-verification-fails", secret, started.Add(time.Second)))
	require.NoError(t, state.FinalizeOperation("op-verification-fails", started.Add(2*time.Second)))
	require.NoError(t, state.RecordOperationVerification("op-verification-fails", true, false, started.Add(3*time.Second)))

	outcome := state.Outcomes["K1"]
	assert.Equal(t, OutcomeNeedsReconciliation, outcome.Status)
	assert.Equal(t, uint64(51), outcome.Metadata.CurrentGeneration)
	assert.Equal(t, uint64(52), outcome.Metadata.IntendedGeneration)
	assert.NotEmpty(t, outcome.Metadata.LifecycleLabel)
	assert.NotEmpty(t, outcome.Metadata.KMSEnvelopeRef)
	assert.Equal(t, VerificationStatePassed, outcome.Metadata.CanaryState)
	assert.Empty(t, state.Hashes)
	assert.Equal(t, VerificationStateFailed, outcome.Metadata.PostconditionState)
	assert.Equal(t, OperationPhaseNeedsReconciliation, state.Phase)
	assert.Nil(t, state.LastSuccess)

	before, err := json.Marshal(state)
	require.NoError(t, err)
	err = state.BeginOperationWithMetadata(
		"op-successor",
		testGenerationMetadata(provider.CapabilityNativeCAS, 51, 52, started.Add(10*time.Minute)),
		[]*provider.Secret{secret},
		started.Add(4*time.Second),
	)
	require.ErrorIs(t, err, ErrOperationPhaseMismatch)
	after, marshalErr := json.Marshal(state)
	require.NoError(t, marshalErr)
	assert.Equal(t, string(before), string(after))
}

func TestSyncState_GenerationDeadlineFailsClosed(t *testing.T) {
	started := time.Date(2026, 8, 24, 10, 40, 0, 0, time.UTC)
	deadline := started.Add(time.Minute)
	secret := &provider.Secret{Key: "K1", Value: "first"}

	t.Run("late acknowledgement", func(t *testing.T) {
		state := &SyncState{Target: "github", ID: "owner/late-ack"}
		metadata := testGenerationMetadata(provider.CapabilityNativeCAS, 55, 56, deadline)
		require.NoError(t, state.BeginOperationWithMetadata("op-late-ack", metadata, []*provider.Secret{secret}, started))
		err := state.RecordKeySuccess("op-late-ack", secret, deadline.Add(time.Nanosecond))
		require.ErrorIs(t, err, ErrOperationDeadlineExceeded)
		assert.Equal(t, OutcomeNeedsReconciliation, state.Outcomes["K1"].Status)
		assert.Empty(t, state.Outcomes["K1"].AcknowledgedHash)
		assert.Empty(t, state.Hashes)
	})

	t.Run("late verification", func(t *testing.T) {
		state := &SyncState{Target: "github", ID: "owner/late-verify"}
		metadata := testGenerationMetadata(provider.CapabilityNativeCAS, 55, 56, deadline)
		require.NoError(t, state.BeginOperationWithMetadata("op-late-verify", metadata, []*provider.Secret{secret}, started))
		require.NoError(t, state.RecordKeySuccess("op-late-verify", secret, started.Add(time.Second)))
		require.NoError(t, state.FinalizeOperation("op-late-verify", started.Add(2*time.Second)))
		err := state.RecordOperationVerification("op-late-verify", true, true, deadline.Add(time.Nanosecond))
		require.ErrorIs(t, err, ErrOperationDeadlineExceeded)
		assert.Equal(t, OutcomeNeedsReconciliation, state.Outcomes["K1"].Status)
		assert.NotEmpty(t, state.Outcomes["K1"].AcknowledgedHash)
		assert.Empty(t, state.Hashes)
		assert.Nil(t, state.LastSuccess)
	})
}

func TestSyncState_GenerationMetadataRejectsInvalidInvariants(t *testing.T) {
	started := time.Date(2026, 8, 24, 10, 45, 0, 0, time.UTC)
	secret := &provider.Secret{Key: "K1", Value: "first"}
	valid := testGenerationMetadata(provider.CapabilityNativeCAS, 60, 61, started.Add(5*time.Minute))
	cases := []OperationMetadata{
		func() OperationMetadata {
			value := valid
			value.IntendedGeneration = value.CurrentGeneration
			return value
		}(),
		func() OperationMetadata {
			value := valid
			value.OldGeneration = value.CurrentGeneration + 1
			return value
		}(),
		func() OperationMetadata { value := valid; value.LifecycleLabel = "invalid label"; return value }(),
		func() OperationMetadata { value := valid; value.KMSEnvelopeRef = "invalid envelope"; return value }(),
		func() OperationMetadata { value := valid; value.Deadline = timePtr(started); return value }(),
		func() OperationMetadata { value := valid; value.Attempts = 4; return value }(),
	}
	for index, metadata := range cases {
		state := &SyncState{Target: "github", ID: fmt.Sprintf("owner/repo-%d", index)}
		require.Error(t, state.BeginOperationWithMetadata("op-invalid", metadata, []*provider.Secret{secret}, started))
		assert.Empty(t, state.OperationID)
	}
}

func testGenerationMetadata(capability provider.Capability, old, current uint64, deadline time.Time) OperationMetadata {
	return OperationMetadata{
		OldGeneration:      old,
		CurrentGeneration:  current,
		IntendedGeneration: current + 1,
		LifecycleLabel:     "source-generation-9",
		KMSEnvelopeRef:     "kms-envelope-ref-9",
		Capability:         capability,
		Deadline:           timePtr(deadline),
		Attempts:           2,
	}
}

func TestStatePathFor_InjectiveIdentityEncoding(t *testing.T) {
	withFakeHome(t)
	first, err := StatePathFor("github", "a-b/c")
	require.NoError(t, err)
	second, err := StatePathFor("github", "a/b-c")
	require.NoError(t, err)
	assert.NotEqual(t, first, second)
}

func TestLoadSyncState_RejectsStoredIdentityMismatch(t *testing.T) {
	withFakeHome(t)
	path, err := StatePathFor("github", "requested")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	data, err := json.Marshal(&SyncState{Target: "github", ID: "stored-other", Hashes: map[string]string{}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	_, err = LoadSyncState("github", "requested")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identity mismatch")
}
