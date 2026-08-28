package syncer

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func coverageRetainedMetadata(now time.Time, capability provider.Capability) OperationMetadata {
	deadline := now.Add(time.Hour)
	return OperationMetadata{
		OldGeneration:      1,
		CurrentGeneration:  2,
		IntendedGeneration: 3,
		LifecycleLabel:     "lifecycle-3",
		KMSEnvelopeRef:     "kms/ref-3",
		Capability:         capability,
		Deadline:           &deadline,
		CanaryState:        VerificationStatePending,
		PostconditionState: VerificationStatePending,
	}
}

func coveragePromotedMetadata(capability provider.Capability, canary, postcondition VerificationState) OperationMetadata {
	return OperationMetadata{
		CurrentGeneration:  3,
		IntendedGeneration: 3,
		Capability:         capability,
		CanaryState:        canary,
		PostconditionState: postcondition,
	}
}

func coverageMetadataState(meta *OperationMetadata, status OutcomeStatus, phase OperationPhase, ack string) SyncState {
	return SyncState{
		Target:      "github",
		ID:          "owner/repo",
		OperationID: "op-metadata",
		Phase:       phase,
		Hashes:      map[string]string{},
		Outcomes: map[string]KeyOutcome{
			"K": {
				Status:           status,
				OperationID:      "op-metadata",
				AcknowledgedHash: ack,
				Metadata:         meta,
			},
		},
	}
}

func writeCoverageStateFile(t *testing.T, state SyncState) {
	t.Helper()
	path, err := StatePathFor(state.Target, state.ID)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	data, err := json.Marshal(state)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func TestSyncState_PersistedMetadataRejectsMalformedInvariants(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	validRetained := func() *OperationMetadata {
		metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
		return &metadata
	}

	tests := []struct {
		name   string
		meta   func() *OperationMetadata
		status OutcomeStatus
		phase  OperationPhase
		ack    string
		mutate func(*OperationMetadata)
	}{
		{
			name:   "legacy acknowledgement hash",
			status: OutcomeSucceeded,
			phase:  OperationPhaseSucceeded,
			ack:    strings.Repeat("a", 64),
		},
		{
			name:   "invalid outcome status",
			meta:   validRetained,
			status: OutcomeStatus("unknown"),
			phase:  OperationPhasePending,
		},
		{
			name:   "invalid capability",
			meta:   validRetained,
			status: OutcomePending,
			phase:  OperationPhasePending,
			mutate: func(metadata *OperationMetadata) { metadata.Capability = provider.Capability("future") },
		},
		{
			name:   "negative attempts",
			meta:   validRetained,
			status: OutcomePending,
			phase:  OperationPhasePending,
			mutate: func(metadata *OperationMetadata) { metadata.Attempts = -1 },
		},
		{
			name:   "too many attempts",
			meta:   validRetained,
			status: OutcomePending,
			phase:  OperationPhasePending,
			mutate: func(metadata *OperationMetadata) { metadata.Attempts = maxOperationAttempts + 1 },
		},
		{
			name:   "invalid canary state",
			meta:   validRetained,
			status: OutcomePending,
			phase:  OperationPhasePending,
			mutate: func(metadata *OperationMetadata) { metadata.CanaryState = VerificationState("unexpected") },
		},
		{
			name: "neither retained nor promoted",
			meta: func() *OperationMetadata {
				metadata := OperationMetadata{Capability: provider.CapabilityNativeCAS, CanaryState: VerificationStatePending, PostconditionState: VerificationStatePending}
				return &metadata
			},
			status: OutcomePending,
			phase:  OperationPhasePending,
		},
		{
			name: "promoted without verification",
			meta: func() *OperationMetadata {
				metadata := coveragePromotedMetadata(provider.CapabilityNativeCAS, VerificationStatePending, VerificationStatePending)
				return &metadata
			},
			status: OutcomeSucceeded,
			phase:  OperationPhaseSucceeded,
		},
		{
			name: "promoted with failed verification",
			meta: func() *OperationMetadata {
				metadata := coveragePromotedMetadata(provider.CapabilityNativeCAS, VerificationStateFailed, VerificationStatePending)
				return &metadata
			},
			status: OutcomeSucceeded,
			phase:  OperationPhaseSucceeded,
		},
		{
			name: "pending operation has verification evidence",
			meta: func() *OperationMetadata {
				metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
				metadata.CanaryState = VerificationStatePassed
				return &metadata
			},
			status: OutcomePending,
			phase:  OperationPhasePending,
		},
		{
			name: "owner risk needs explicit state",
			meta: func() *OperationMetadata {
				metadata := coverageRetainedMetadata(now, provider.CapabilityOwnerRiskGate)
				return &metadata
			},
			status: OutcomeNeedsReconciliation,
			phase:  OperationPhaseNeedsReconciliation,
		},
		{
			name: "owner risk cannot use generic pending state",
			meta: func() *OperationMetadata {
				metadata := coverageRetainedMetadata(now, provider.CapabilityOwnerRiskGate)
				metadata.ReconciliationState = ReconciliationStatePending
				return &metadata
			},
			status: OutcomeNeedsReconciliation,
			phase:  OperationPhaseNeedsReconciliation,
		},
		{
			name: "native capability cannot use pending state for success",
			meta: func() *OperationMetadata {
				metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
				metadata.ReconciliationState = ReconciliationStatePending
				return &metadata
			},
			status: OutcomeSucceeded,
			phase:  OperationPhasePending,
		},
		{
			name: "owner risk required state on native capability",
			meta: func() *OperationMetadata {
				metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
				metadata.ReconciliationState = ReconciliationStateOwnerRiskRequired
				return &metadata
			},
			status: OutcomeNeedsReconciliation,
			phase:  OperationPhaseNeedsReconciliation,
		},
		{
			name: "owner risk approval state on native capability",
			meta: func() *OperationMetadata {
				metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
				metadata.ReconciliationState = ReconciliationStateApproved
				return &metadata
			},
			status: OutcomeNeedsReconciliation,
			phase:  OperationPhaseNeedsReconciliation,
		},
		{
			name: "unknown reconciliation state",
			meta: func() *OperationMetadata {
				metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
				metadata.ReconciliationState = ReconciliationState("unknown")
				return &metadata
			},
			status: OutcomePending,
			phase:  OperationPhasePending,
		},
		{
			name: "blocked capability cannot succeed",
			meta: func() *OperationMetadata {
				metadata := coverageRetainedMetadata(now, provider.CapabilityBlocked)
				return &metadata
			},
			status: OutcomeSucceeded,
			phase:  OperationPhasePending,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withFakeHome(t)
			var metadata *OperationMetadata
			if test.meta != nil {
				metadata = test.meta()
				if test.mutate != nil {
					test.mutate(metadata)
				}
			}
			state := coverageMetadataState(metadata, test.status, test.phase, test.ack)
			err := SaveSyncState(&state)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "secret")
		})
	}
}

func TestSyncState_PersistedMetadataPhaseContracts(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 30, 0, 0, time.UTC)
	ack := strings.Repeat("b", 64)
	tests := []struct {
		name  string
		state SyncState
		want  error
	}{
		{
			name: "succeeded phase requires promoted metadata",
			state: func() SyncState {
				metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
				metadata.CanaryState = VerificationStatePassed
				metadata.PostconditionState = VerificationStatePassed
				return coverageMetadataState(&metadata, OutcomeSucceeded, OperationPhaseSucceeded, ack)
			}(),
			want: errors.New("success is not promoted"),
		},
		{
			name: "awaiting verification needs metadata",
			state: SyncState{
				Target: "github", ID: "owner/no-metadata", OperationID: "op-await", Phase: OperationPhaseAwaitingVerification,
				Outcomes: map[string]KeyOutcome{"K": {Status: OutcomeSucceeded, OperationID: "op-await"}},
			},
			want: ErrOperationVerificationRequired,
		},
		{
			name: "awaiting verification rejects failed evidence",
			state: func() SyncState {
				metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
				metadata.CanaryState = VerificationStateFailed
				return coverageMetadataState(&metadata, OutcomeSucceeded, OperationPhaseAwaitingVerification, ack)
			}(),
			want: errors.New("invalid verification wait"),
		},
		{
			name: "pending phase rejects premature promotion",
			state: func() SyncState {
				metadata := coveragePromotedMetadata(provider.CapabilityNativeCAS, VerificationStatePassed, VerificationStatePassed)
				return coverageMetadataState(&metadata, OutcomeSucceeded, OperationPhasePending, "")
			}(),
			want: errors.New("premature generation promotion"),
		},
		{
			name: "retained generation cannot be orphaned",
			state: func() SyncState {
				metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
				state := coverageMetadataState(&metadata, OutcomePending, OperationPhasePending, "")
				state.OperationID = "op-current"
				state.Outcomes["K"] = KeyOutcome{Status: OutcomePending, OperationID: "op-old", Metadata: &metadata}
				return state
			}(),
			want: errors.New("orphaned retained generation"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withFakeHome(t)
			writeCoverageStateFile(t, test.state)
			_, err := LoadSyncState(test.state.Target, test.state.ID)
			require.Error(t, err)
			assert.ErrorContains(t, err, test.want.Error())
		})
	}
}

func TestSyncState_BeginAndVerifyRejectInvalidTransitions(t *testing.T) {
	started := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	secret := &provider.Secret{Key: "K", Value: "value"}

	t.Run("blank operation id", func(t *testing.T) {
		state := &SyncState{}
		require.ErrorContains(t, state.BeginOperation(" \t", []*provider.Secret{secret}, started), "operation id is required")
	})
	t.Run("nil secret", func(t *testing.T) {
		state := &SyncState{}
		require.ErrorContains(t, state.BeginOperation("op", []*provider.Secret{nil}, started), "nil secret")
	})
	t.Run("retained metadata blocks successor", func(t *testing.T) {
		state := &SyncState{}
		metadata := coverageRetainedMetadata(started, provider.CapabilityNativeCAS)
		require.NoError(t, state.BeginOperationWithMetadata("op-first", metadata, []*provider.Secret{secret}, started))
		require.ErrorIs(t, state.BeginOperation("op-second", []*provider.Secret{secret}, started.Add(time.Minute)), ErrOperationPhaseMismatch)
	})
	t.Run("needs reconciliation cannot be recorded after success", func(t *testing.T) {
		state := &SyncState{}
		require.NoError(t, state.BeginOperation("op", []*provider.Secret{secret}, started))
		require.NoError(t, state.RecordSuccess("op", []*provider.Secret{secret}, started.Add(time.Second)))
		require.ErrorIs(t, state.RecordNeedsReconciliation("op", []*provider.Secret{secret}, started.Add(2*time.Second)), ErrOperationPhaseMismatch)
	})
	t.Run("metadata acknowledgement must match", func(t *testing.T) {
		state := &SyncState{}
		metadata := coverageRetainedMetadata(started, provider.CapabilityNativeCAS)
		require.NoError(t, state.BeginOperationWithMetadata("op", metadata, []*provider.Secret{secret}, started))
		require.NoError(t, state.RecordKeySuccess("op", secret, started.Add(time.Second)))
		secret.Value = "changed"
		require.ErrorIs(t, state.RecordKeySuccess("op", secret, started.Add(2*time.Second)), ErrOperationKeyMismatch)
	})
	t.Run("unapproved reconciliation cannot be acknowledged", func(t *testing.T) {
		state := &SyncState{}
		metadata := coverageRetainedMetadata(started, provider.CapabilityNativeCAS)
		require.NoError(t, state.BeginOperationWithMetadata("op", metadata, []*provider.Secret{secret}, started))
		require.NoError(t, state.RecordKeyNeedsReconciliation("op", secret, started.Add(time.Second)))
		require.ErrorIs(t, state.RecordKeySuccess("op", secret, started.Add(2*time.Second)), ErrOperationPhaseMismatch)
	})

	t.Run("owner risk approval validates ownership and status", func(t *testing.T) {
		state := &SyncState{}
		metadata := coverageRetainedMetadata(started, provider.CapabilityOwnerRiskGate)
		require.NoError(t, state.BeginOperationWithMetadata("op", metadata, []*provider.Secret{secret}, started))
		require.ErrorIs(t, state.ApproveOwnerRiskReconciliation("op", "missing", started), ErrOperationKeyMismatch)
		require.ErrorIs(t, state.ApproveOwnerRiskReconciliation("op", "K", started), ErrOperationPhaseMismatch)
		require.NoError(t, state.RecordKeyNeedsReconciliation("op", secret, started.Add(time.Second)))
		require.NoError(t, state.ApproveOwnerRiskReconciliation("op", "K", started.Add(2*time.Second)))
		require.NoError(t, state.ApproveOwnerRiskReconciliation("op", "K", started.Add(3*time.Second)))
	})
	t.Run("approval rejects non-owner metadata", func(t *testing.T) {
		state := &SyncState{}
		metadata := coverageRetainedMetadata(started, provider.CapabilityNativeCAS)
		require.NoError(t, state.BeginOperationWithMetadata("op", metadata, []*provider.Secret{secret}, started))
		require.NoError(t, state.RecordKeyNeedsReconciliation("op", secret, started.Add(time.Second)))
		require.ErrorIs(t, state.ApproveOwnerRiskReconciliation("op", "K", started.Add(2*time.Second)), ErrOperationCapabilityInvalid)
	})
	t.Run("verification requires awaiting phase", func(t *testing.T) {
		state := &SyncState{}
		require.NoError(t, state.BeginOperation("op", []*provider.Secret{secret}, started))
		require.ErrorIs(t, state.RecordOperationVerification("op", true, true, started.Add(time.Second)), ErrOperationPhaseMismatch)
	})
	t.Run("verification rejects malformed acknowledgement", func(t *testing.T) {
		state := &SyncState{}
		metadata := coverageRetainedMetadata(started, provider.CapabilityNativeCAS)
		require.NoError(t, state.BeginOperationWithMetadata("op", metadata, []*provider.Secret{secret}, started))
		require.NoError(t, state.RecordKeySuccess("op", secret, started.Add(time.Second)))
		require.NoError(t, state.FinalizeOperation("op", started.Add(2*time.Second)))
		state.Outcomes["K"] = func() KeyOutcome {
			outcome := state.Outcomes["K"]
			outcome.AcknowledgedHash = "bad"
			return outcome
		}()
		require.ErrorIs(t, state.RecordOperationVerification("op", true, true, started.Add(3*time.Second)), ErrOperationPhaseMismatch)
	})
	t.Run("verification with no owned outcomes is empty", func(t *testing.T) {
		state := &SyncState{OperationID: "op", Phase: OperationPhaseAwaitingVerification, Outcomes: map[string]KeyOutcome{}}
		require.ErrorIs(t, state.RecordOperationVerification("op", true, true, started), ErrOperationEmpty)
	})
	t.Run("canary failure retains reconciliation", func(t *testing.T) {
		state := &SyncState{}
		metadata := coverageRetainedMetadata(started, provider.CapabilityNativeCAS)
		require.NoError(t, state.BeginOperationWithMetadata("op", metadata, []*provider.Secret{secret}, started))
		require.NoError(t, state.RecordKeySuccess("op", secret, started.Add(time.Second)))
		require.NoError(t, state.FinalizeOperation("op", started.Add(2*time.Second)))
		require.NoError(t, state.RecordOperationVerification("op", false, true, started.Add(3*time.Second)))
		assert.Equal(t, OperationPhaseNeedsReconciliation, state.Phase)
		assert.Equal(t, VerificationStateFailed, state.Outcomes["K"].Metadata.CanaryState)
	})
	t.Run("mixed legacy and metadata outcomes are rejected", func(t *testing.T) {
		metadata := coverageRetainedMetadata(started, provider.CapabilityNativeCAS)
		metadata.CanaryState = VerificationStatePassed
		metadata.PostconditionState = VerificationStatePassed
		state := &SyncState{
			OperationID: "op",
			Phase:       OperationPhasePending,
			Hashes:      map[string]string{},
			Outcomes: map[string]KeyOutcome{
				"legacy":   {Status: OutcomeSucceeded, OperationID: "op"},
				"metadata": {Status: OutcomeSucceeded, OperationID: "op", AcknowledgedHash: strings.Repeat("c", 64), Metadata: &metadata},
			},
		}
		require.ErrorIs(t, state.FinalizeOperation("op", started), ErrOperationPhaseMismatch)
	})
}

func TestSyncState_NewOperationIDIsOpaqueAndUnique(t *testing.T) {
	first, err := NewOperationID()
	require.NoError(t, err)
	second, err := NewOperationID()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(first, "op-"))
	assert.True(t, strings.HasPrefix(second, "op-"))
	assert.Len(t, first, len("op-")+32)
	assert.Len(t, second, len("op-")+32)
	assert.NotEqual(t, first, second)
	assert.NotContains(t, first, "secret")
}

func TestSyncState_SaveRejectsUncreatableStateDirectory(t *testing.T) {
	home := withFakeHome(t)
	stateDir := filepath.Join(home, ".skret", "sync-state")
	require.NoError(t, os.MkdirAll(filepath.Dir(stateDir), 0o700))
	require.NoError(t, os.WriteFile(stateDir, []byte("not-a-directory"), 0o600))

	err := SaveSyncState(&SyncState{Target: "github", ID: "owner/repo", Hashes: map[string]string{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create sync state dir")
	assert.NotContains(t, err.Error(), "not-a-directory")
}

func TestSyncState_LoadRejectsDirectoryAtStatePath(t *testing.T) {
	withFakeHome(t)
	path, err := StatePathFor("github", "owner/repo")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.Mkdir(path, 0o700))

	_, err = LoadSyncState("github", "owner/repo")
	require.ErrorContains(t, err, "read sync state")
	assert.NotContains(t, err.Error(), "secret")
}

func TestSyncState_FinalizeConvertsUnapprovedOwnerRiskSuccessToReconciliation(t *testing.T) {
	now := time.Date(2026, 8, 24, 20, 0, 0, 0, time.UTC)
	metadata := coverageRetainedMetadata(now, provider.CapabilityOwnerRiskGate)
	metadata.CanaryState = VerificationStatePassed
	metadata.PostconditionState = VerificationStatePassed
	state := &SyncState{
		OperationID: "op-owner-risk-finalize",
		Phase:       OperationPhasePending,
		Outcomes: map[string]KeyOutcome{
			"K": {
				Status:           OutcomeSucceeded,
				OperationID:      "op-owner-risk-finalize",
				AcknowledgedHash: strings.Repeat("d", 64),
				Metadata:         &metadata,
			},
		},
	}

	require.NoError(t, state.FinalizeOperation("op-owner-risk-finalize", now))
	assert.Equal(t, OperationPhaseNeedsReconciliation, state.Phase)
	assert.Equal(t, OutcomeNeedsReconciliation, state.Outcomes["K"].Status)
	assert.Equal(t, ReconciliationStateOwnerRiskRequired, state.Outcomes["K"].Metadata.ReconciliationState)
	assert.Empty(t, state.Hashes)
}

func TestSyncState_StateMachineAndPersistenceErrorMatrix(t *testing.T) {
	now := time.Date(2026, 8, 24, 20, 30, 0, 0, time.UTC)
	secret := &provider.Secret{Key: "K", Value: "value"}

	t.Run("metadata defaults old generation to current", func(t *testing.T) {
		metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
		metadata.OldGeneration = 0
		state := &SyncState{}
		require.NoError(t, state.BeginOperationWithMetadata("op-default-old", metadata, []*provider.Secret{secret}, now))
		assert.Equal(t, metadata.CurrentGeneration, state.Outcomes["K"].Metadata.OldGeneration)
	})
	t.Run("interrupted empty-operation outcomes retain prior ownership", func(t *testing.T) {
		state := &SyncState{
			OperationID: "op-old",
			Phase:       OperationPhasePending,
			Outcomes: map[string]KeyOutcome{
				"K": {Status: OutcomePending, UpdatedAt: now},
			},
		}
		newSecret := &provider.Secret{Key: "new", Value: "value"}
		require.NoError(t, state.BeginOperation("op-new", []*provider.Secret{newSecret}, now.Add(time.Minute)))
		assert.Equal(t, OutcomeNeedsReconciliation, state.Outcomes["K"].Status)
		assert.Equal(t, "op-old", state.Outcomes["K"].OperationID)
	})
	t.Run("interrupted promoted metadata gets pending reconciliation state", func(t *testing.T) {
		metadata := coveragePromotedMetadata(provider.CapabilityNativeCAS, VerificationStatePassed, VerificationStatePassed)
		state := &SyncState{
			OperationID: "op-old",
			Phase:       OperationPhasePending,
			Outcomes: map[string]KeyOutcome{
				"K": {Status: OutcomePending, Metadata: &metadata, UpdatedAt: now},
			},
		}
		newSecret := &provider.Secret{Key: "new", Value: "value"}
		require.NoError(t, state.BeginOperation("op-new", []*provider.Secret{newSecret}, now.Add(time.Minute)))
		assert.Equal(t, ReconciliationStatePending, state.Outcomes["K"].Metadata.ReconciliationState)
	})

	t.Run("empty batches are rejected before mutation", func(t *testing.T) {
		state := &SyncState{}
		require.NoError(t, state.BeginOperation("op-empty-batch", []*provider.Secret{secret}, now))
		require.ErrorIs(t, state.RecordSuccess("op-empty-batch", nil, now.Add(time.Second)), ErrOperationEmpty)
		require.ErrorIs(t, state.RecordNeedsReconciliation("op-empty-batch", nil, now.Add(time.Second)), ErrOperationEmpty)
	})

	t.Run("duplicate metadata acknowledgement detects second value mismatch", func(t *testing.T) {
		state := &SyncState{}
		metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
		require.NoError(t, state.BeginOperationWithMetadata("op-duplicate", metadata, []*provider.Secret{secret}, now))
		changed := &provider.Secret{Key: "K", Value: "changed"}
		require.ErrorIs(t, state.RecordSuccess("op-duplicate", []*provider.Secret{secret, changed}, now.Add(time.Second)), ErrOperationKeyMismatch)
		assert.Equal(t, OutcomeSucceeded, state.Outcomes["K"].Status)
	})

	t.Run("record reconciliation validates persisted metadata", func(t *testing.T) {
		invalid := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
		invalid.Capability = provider.Capability("invalid")
		state := &SyncState{
			OperationID: "op-invalid-record",
			Phase:       OperationPhasePending,
			Outcomes: map[string]KeyOutcome{
				"K": {Status: OutcomePending, OperationID: "op-invalid-record", Metadata: &invalid},
			},
		}
		require.Error(t, state.RecordKeyNeedsReconciliation("op-invalid-record", secret, now))
	})

	t.Run("reconciliation cannot be recorded after key success", func(t *testing.T) {
		state := &SyncState{}
		require.NoError(t, state.BeginOperation("op-success-then-reconcile", []*provider.Secret{secret}, now))
		require.NoError(t, state.RecordKeySuccess("op-success-then-reconcile", secret, now.Add(time.Second)))
		require.ErrorIs(t, state.RecordKeyNeedsReconciliation("op-success-then-reconcile", secret, now.Add(2*time.Second)), ErrOperationPhaseMismatch)
	})

	t.Run("approval validates persisted metadata", func(t *testing.T) {
		invalid := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
		invalid.Capability = provider.Capability("invalid")
		state := &SyncState{
			OperationID: "op-invalid-approval",
			Phase:       OperationPhaseNeedsReconciliation,
			Outcomes: map[string]KeyOutcome{
				"K": {Status: OutcomeNeedsReconciliation, OperationID: "op-invalid-approval", Metadata: &invalid},
			},
		}
		require.Error(t, state.ApproveOwnerRiskReconciliation("op-invalid-approval", "K", now))
	})

	t.Run("verification rejects stale operation", func(t *testing.T) {
		state := &SyncState{OperationID: "op-current", Phase: OperationPhaseAwaitingVerification}
		require.ErrorIs(t, state.RecordOperationVerification("op-stale", true, true, now), ErrOperationMismatch)
	})

	t.Run("verification skips outcomes owned by another operation", func(t *testing.T) {
		metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
		state := &SyncState{
			OperationID: "op-verify",
			Phase:       OperationPhaseAwaitingVerification,
			Outcomes: map[string]KeyOutcome{
				"current": {Status: OutcomeSucceeded, OperationID: "op-verify", AcknowledgedHash: strings.Repeat("a", 64), Metadata: &metadata},
				"old":     {Status: OutcomePending, OperationID: "op-old"},
			},
		}
		require.NoError(t, state.RecordOperationVerification("op-verify", true, true, now.Add(time.Second)))
		assert.Equal(t, OutcomePending, state.Outcomes["old"].Status)
		assert.Equal(t, OperationPhaseSucceeded, state.Phase)
	})

	t.Run("finalize rejects invalid metadata and missing acknowledgement", func(t *testing.T) {
		invalid := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
		invalid.Capability = provider.Capability("invalid")
		state := &SyncState{
			OperationID: "op-invalid-finalize",
			Outcomes: map[string]KeyOutcome{
				"K": {Status: OutcomeSucceeded, OperationID: "op-invalid-finalize", Metadata: &invalid},
			},
		}
		require.Error(t, state.FinalizeOperation("op-invalid-finalize", now))

		valid := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
		state = &SyncState{
			OperationID: "op-missing-ack",
			Outcomes: map[string]KeyOutcome{
				"K": {Status: OutcomeSucceeded, OperationID: "op-missing-ack", Metadata: &valid},
			},
		}
		require.ErrorContains(t, state.FinalizeOperation("op-missing-ack", now), "missing acknowledgement hash")
	})

	t.Run("load initializes absent hash map", func(t *testing.T) {
		withFakeHome(t)
		state := SyncState{Target: "github", ID: "owner/no-hashes"}
		writeCoverageStateFile(t, state)
		loaded, err := LoadSyncState(state.Target, state.ID)
		require.NoError(t, err)
		require.NotNil(t, loaded.Hashes)
		assert.Empty(t, loaded.Hashes)
	})
}

func TestOperationMetadataValidateRejectsEveryStartInvariant(t *testing.T) {
	now := time.Date(2026, 8, 24, 22, 30, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*OperationMetadata)
	}{
		{"generation order", func(metadata *OperationMetadata) { metadata.IntendedGeneration = metadata.CurrentGeneration }},
		{"old generation order", func(metadata *OperationMetadata) { metadata.OldGeneration = metadata.CurrentGeneration + 1 }},
		{"missing capability", func(metadata *OperationMetadata) { metadata.Capability = "" }},
		{"invalid capability", func(metadata *OperationMetadata) { metadata.Capability = provider.Capability("future") }},
		{"invalid lifecycle", func(metadata *OperationMetadata) { metadata.LifecycleLabel = "bad label" }},
		{"invalid kms reference", func(metadata *OperationMetadata) { metadata.KMSEnvelopeRef = "bad reference" }},
		{"missing deadline", func(metadata *OperationMetadata) { metadata.Deadline = nil }},
		{"late deadline", func(metadata *OperationMetadata) { deadline := now; metadata.Deadline = &deadline }},
		{"negative attempts", func(metadata *OperationMetadata) { metadata.Attempts = -1 }},
		{"excessive attempts", func(metadata *OperationMetadata) { metadata.Attempts = maxOperationAttempts + 1 }},
		{"reconciliation state", func(metadata *OperationMetadata) { metadata.ReconciliationState = ReconciliationStatePending }},
		{"canary state", func(metadata *OperationMetadata) { metadata.CanaryState = VerificationStatePassed }},
		{"postcondition state", func(metadata *OperationMetadata) { metadata.PostconditionState = VerificationStateFailed }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
			test.mutate(&metadata)
			require.Error(t, metadata.validate(now))
		})
	}
}

func TestSyncState_PersistedAcknowledgementAndOwnershipErrors(t *testing.T) {
	now := time.Date(2026, 8, 24, 22, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		state SyncState
	}{
		{
			name: "invalid retained acknowledgement",
			state: func() SyncState {
				metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
				return coverageMetadataState(&metadata, OutcomePending, OperationPhasePending, "bad")
			}(),
		},
		{
			name: "orphaned retained generation",
			state: func() SyncState {
				metadata := coverageRetainedMetadata(now, provider.CapabilityNativeCAS)
				state := coverageMetadataState(&metadata, OutcomePending, OperationPhasePending, "")
				state.Outcomes["K"] = KeyOutcome{Status: OutcomePending, OperationID: "op-old", Metadata: &metadata}
				state.OperationID = "op-current"
				return state
			}(),
		},
		{
			name: "succeeded phase retains acknowledgement",
			state: func() SyncState {
				metadata := coveragePromotedMetadata(provider.CapabilityNativeCAS, VerificationStatePassed, VerificationStatePassed)
				return coverageMetadataState(&metadata, OutcomeSucceeded, OperationPhaseSucceeded, strings.Repeat("a", 64))
			}(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withFakeHome(t)
			writeCoverageStateFile(t, test.state)
			_, err := LoadSyncState(test.state.Target, test.state.ID)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "value")
		})
	}
}
