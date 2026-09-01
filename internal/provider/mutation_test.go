package provider_test

import (
	"errors"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
)

func TestPartialCommitError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *provider.PartialCommitError
		want string
	}{
		{
			name: "nil receiver",
			want: "provider mutation partially committed",
		},
		{
			name: "committed value needs tag reconciliation",
			err: &provider.PartialCommitError{
				Provider:        "aws",
				Key:             "/app/token",
				Version:         12,
				ObservedVersion: 12,
				TagState:        provider.TagReconciliationRequired,
			},
			want: `aws: value committed for "/app/token" at version 12 (observed version 12); tag reconciliation required`,
		},
		{
			name: "committed value has unknown tag state",
			err: &provider.PartialCommitError{
				Provider:        "aws",
				Key:             "/app/token",
				Version:         12,
				ObservedVersion: 0,
				TagState:        provider.TagReconciliationUnknown,
			},
			want: `aws: value committed for "/app/token" at version 12 (observed version 0); tag reconciliation state unknown`,
		},
		{
			name: "mutation outcome is unknown",
			err: &provider.PartialCommitError{
				Provider:        "aws",
				Key:             "/app/token",
				PreVersion:      11,
				CommitState:     provider.MutationCommitUnknown,
				ObservedVersion: 0,
				TagState:        provider.TagReconciliationUnknown,
			},
			want: `aws: mutation outcome unknown for "/app/token" (pre-version 11, observed version 0); tag reconciliation state unknown`,
		},
		{
			name: "provider supplied tag state",
			err: &provider.PartialCommitError{
				Provider:        "local",
				Key:             "token",
				Version:         3,
				ObservedVersion: 3,
				TagState:        "metadata rejected",
			},
			want: `local: value committed for "token" at version 3 (observed version 3); metadata rejected`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}
}

func TestPartialCommitError_Unwrap(t *testing.T) {
	err := &provider.PartialCommitError{}
	assert.True(t, errors.Is(err, provider.ErrPartialCommit))
}
