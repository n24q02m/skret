package syncer

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// coverageDeterministicHashKey pins the hash key so no keyring, environment
// or home-directory material is consulted.
func coverageDeterministicHashKey(t *testing.T) {
	t.Helper()
	resetHashKeyForTest(t)
	hashKeyOverride = bytes.Repeat([]byte{0x42}, 32)
}

// coverageWithoutHome makes os.UserHomeDir fail for the current platform.
func coverageWithoutHome(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", "")
		t.Setenv("HOMEDRIVE", "")
		t.Setenv("HOMEPATH", "")
	} else {
		t.Setenv("HOME", "")
	}
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("platform still resolves a home directory without HOME")
	}
}

func TestSyncState_OperationMutatorsRejectForeignOperation(t *testing.T) {
	coverageDeterministicHashKey(t)
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	secret := &provider.Secret{Key: "K", Value: "v"}
	state := &SyncState{Target: "github", ID: "owner/repo"}
	require.NoError(t, state.BeginOperation("op-current", []*provider.Secret{secret}, now))

	assert.ErrorIs(t, state.RecordNeedsReconciliation("op-other", []*provider.Secret{secret}, now), ErrOperationMismatch)
	assert.ErrorIs(t, state.RecordKeyNeedsReconciliation("op-other", secret, now), ErrOperationMismatch)
	assert.ErrorIs(t, state.ApproveOwnerRiskReconciliation("op-other", "K", now), ErrOperationMismatch)
	assert.Equal(t, OutcomePending, state.Outcomes["K"].Status)
	assert.Equal(t, OperationPhasePending, state.Phase)
}

func TestSyncState_RecordRejectsCorruptedOutcomeMetadata(t *testing.T) {
	coverageDeterministicHashKey(t)
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	secret := &provider.Secret{Key: "K", Value: "v"}
	begin := func(t *testing.T) *SyncState {
		t.Helper()
		state := &SyncState{Target: "github", ID: "owner/repo"}
		require.NoError(t, state.BeginOperationWithMetadata("op-meta", coverageRetainedMetadata(now, provider.CapabilityNativeCAS), []*provider.Secret{secret}, now))
		state.Outcomes["K"].Metadata.Attempts = 99
		return state
	}

	state := begin(t)
	err := state.RecordNeedsReconciliation("op-meta", []*provider.Secret{secret}, now.Add(time.Minute))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attempts are out of range")
	assert.Equal(t, OutcomePending, state.Outcomes["K"].Status)

	state = begin(t)
	err = state.RecordSuccess("op-meta", []*provider.Secret{secret}, now.Add(time.Minute))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attempts are out of range")
	assert.Equal(t, OutcomePending, state.Outcomes["K"].Status)
	assert.Empty(t, state.Outcomes["K"].AcknowledgedHash)
}

func TestSyncState_RecordSuccessRejectsUnapprovedReconciliation(t *testing.T) {
	coverageDeterministicHashKey(t)
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	secret := &provider.Secret{Key: "K", Value: "v"}
	state := &SyncState{Target: "github", ID: "owner/repo"}
	require.NoError(t, state.BeginOperation("op-plain", []*provider.Secret{secret}, now))
	require.NoError(t, state.RecordKeyNeedsReconciliation("op-plain", secret, now))

	assert.ErrorIs(t, state.RecordSuccess("op-plain", []*provider.Secret{secret}, now), ErrOperationPhaseMismatch)
	assert.Equal(t, OutcomeNeedsReconciliation, state.Outcomes["K"].Status)
	assert.Empty(t, state.Hashes)
}

func TestSyncState_MetadataHelpersHandleNilAndBoundaryValues(t *testing.T) {
	var metadata *OperationMetadata
	assert.NoError(t, metadata.validate(time.Now()))
	assert.NoError(t, metadata.validatePersisted(OutcomeSucceeded))
	assert.NotPanics(t, func() { promoteMetadata(nil) })

	assert.False(t, validOperationReference(""))
	assert.False(t, validOperationReference(strings.Repeat("a", 513)))
	assert.True(t, validOperationReference(strings.Repeat("a", 512)))

	assert.False(t, validAcknowledgedHash(strings.Repeat("A", 64)))
	assert.False(t, validAcknowledgedHash(strings.Repeat("g", 64)))
	assert.True(t, validAcknowledgedHash(strings.Repeat("a", 64)))

	blocked := KeyOutcome{Status: OutcomeSucceeded, Metadata: &OperationMetadata{Capability: provider.CapabilityBlocked}}
	assert.False(t, outcomeCapabilityAllowsSuccess(blocked))
}

func TestSyncState_FinalizeAndPendingWithoutOwnedOutcomes(t *testing.T) {
	state := &SyncState{OperationID: "op-empty", Phase: OperationPhaseNeedsReconciliation, Outcomes: map[string]KeyOutcome{
		"OTHER": {Status: OutcomePending, OperationID: "op-previous"},
	}}
	assert.ErrorIs(t, state.FinalizeOperation("op-empty", time.Now()), ErrOperationEmpty)
	assert.False(t, state.operationPending())

	state.Outcomes["MINE"] = KeyOutcome{Status: OutcomePending, OperationID: "op-empty"}
	assert.True(t, state.operationPending())
}

func TestSaveSyncState_RejectsInvalidOperationIdentity(t *testing.T) {
	coverageDeterministicHashKey(t)
	home := withFakeHome(t)
	cases := map[string]func(*SyncState){
		"operation method": func(s *SyncState) { s.OperationMethod = "bad method" },
		"source identity":  func(s *SyncState) { s.SourceIdentity = strings.Repeat("x", 513) },
		"source digest":    func(s *SyncState) { s.SourceDigest = "not-a-digest" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			state := &SyncState{Target: "github", ID: "owner/repo", Hashes: map[string]string{}}
			mutate(state)
			err := SaveSyncState(state)
			require.Error(t, err)
			assert.Contains(t, err.Error(), name)
			assert.NoDirExists(t, filepath.Join(home, ".skret", "sync-state"))
		})
	}
}

func TestSaveSyncState_RoundTripsOtherOperationPromotedMetadata(t *testing.T) {
	coverageDeterministicHashKey(t)
	withFakeHome(t)
	promoted := coveragePromotedMetadata(provider.CapabilityNativeCAS, VerificationStatePassed, VerificationStatePassed)
	state := &SyncState{
		Target:      "github",
		ID:          "owner/repo",
		OperationID: "op-current",
		Phase:       OperationPhaseSucceeded,
		Hashes:      map[string]string{"OLD": strings.Repeat("a", 64)},
		Outcomes: map[string]KeyOutcome{
			"OLD": {Status: OutcomeSucceeded, OperationID: "op-previous", Metadata: &promoted},
		},
	}
	require.NoError(t, SaveSyncState(state))

	loaded, err := LoadSyncState("github", "owner/repo")
	require.NoError(t, err)
	require.Contains(t, loaded.Outcomes, "OLD")
	assert.Equal(t, "op-previous", loaded.Outcomes["OLD"].OperationID)
	assert.Equal(t, uint64(3), loaded.Outcomes["OLD"].Metadata.CurrentGeneration)
	assert.Equal(t, strings.Repeat("a", 64), loaded.Hashes["OLD"])
}

func TestSyncState_PersistenceFailsWithoutHomeDirectory(t *testing.T) {
	coverageDeterministicHashKey(t)
	coverageWithoutHome(t)

	_, err := LoadSyncState("github", "owner/repo")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user home dir")

	err = SaveSyncState(&SyncState{Target: "github", ID: "owner/repo"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user home dir")
}

func TestSaveSyncState_ReportsUnwritableStateDirectory(t *testing.T) {
	coverageDeterministicHashKey(t)
	withFakeHome(t)
	path, err := StatePathFor("github", "owner/repo")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	faultBlockCreate(t, filepath.Dir(path))

	err = SaveSyncState(&SyncState{Target: "github", ID: "owner/repo", Hashes: map[string]string{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create sync state temp")
	assert.NoFileExists(t, path)
}

func TestSourceDigest_TreatsNilSecretAsDistinctOrderIndependentEntry(t *testing.T) {
	coverageDeterministicHashKey(t)
	secret := &provider.Secret{Key: "K", Value: "v"}

	withNil := SourceDigest([]*provider.Secret{nil, secret})
	assert.Equal(t, withNil, SourceDigest([]*provider.Secret{secret, nil}))
	assert.NotEqual(t, withNil, SourceDigest([]*provider.Secret{secret}))
	assert.True(t, validAcknowledgedHash(withNil))
}

func TestHashKeyFile_ReportsUnwritableKeyPath(t *testing.T) {
	home := withFakeHome(t)
	keyPath := filepath.Join(home, ".skret", "sync-hash.key")
	require.NoError(t, os.MkdirAll(keyPath, 0o700))

	key, err := hashKeyFile()
	require.Error(t, err)
	assert.Nil(t, key)
	assert.DirExists(t, keyPath)
}
