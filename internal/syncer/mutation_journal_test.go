package syncer

import (
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSourceDigestBindsSortedKeysAndValueHashesWithoutValues(t *testing.T) {
	first := []*provider.Secret{
		{Key: "B", Value: "bravo-secret"},
		{Key: "A", Value: "alpha-secret"},
	}
	second := []*provider.Secret{
		{Key: "A", Value: "alpha-secret"},
		{Key: "B", Value: "bravo-secret"},
	}
	assert.Equal(t, SourceDigest(first), SourceDigest(second))
	digest := SourceDigest(first)
	require.Len(t, digest, 64)
	assert.NotContains(t, digest, "alpha-secret")
	assert.NotContains(t, digest, "bravo-secret")
	assert.NotContains(t, digest, " ")
	assert.Equal(t, digest, strings.ToLower(digest))
	assert.NotEqual(t, digest, SourceDigest(append(first, &provider.Secret{Key: "C", Value: "charlie-secret"})))
}

func TestSyncStateRequiresReconciliationForIncompleteExternalOperation(t *testing.T) {
	state := &SyncState{
		OperationID: "op-ambiguous",
		Phase:       OperationPhaseNeedsReconciliation,
		Outcomes: map[string]KeyOutcome{
			"KEY": {OperationID: "op-ambiguous", Status: OutcomeNeedsReconciliation},
		},
	}
	assert.True(t, state.RequiresReconciliation())

	state.Phase = OperationPhasePending
	state.Outcomes["KEY"] = KeyOutcome{OperationID: "op-ambiguous", Status: OutcomePending}
	assert.True(t, state.RequiresReconciliation())

	state.Outcomes["KEY"] = KeyOutcome{OperationID: "op-ambiguous", Status: OutcomeSucceeded}
	assert.False(t, state.RequiresReconciliation(), "all-success pending state is recoverable by finalization")

	state.Phase = OperationPhaseSucceeded
	assert.False(t, state.RequiresReconciliation())
}
