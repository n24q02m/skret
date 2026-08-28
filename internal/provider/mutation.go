package provider

import (
	"errors"
	"fmt"
)

// ErrPartialCommit marks a provider write whose value committed but whose
// follow-up metadata operation needs reconciliation. Callers must not retry
// the original write blindly.
var ErrPartialCommit = errors.New("provider mutation partially committed")

const (
	TagReconciliationRequired = "tag_reconciliation_required"
	TagReconciliationUnknown  = "tag_reconciliation_unknown"
)
const MutationCommitUnknown = "unknown"

// PartialCommitError carries only non-secret mutation state. The provider
// value is intentionally absent: a successful write is represented by its
// version and the tag readback classification.
type PartialCommitError struct {
	Provider        string
	Key             string
	PreVersion      int64
	CommitState     string
	Version         int64
	ObservedVersion int64
	TagState        string
}

func (e *PartialCommitError) Error() string {
	if e == nil {
		return "provider mutation partially committed"
	}
	state := e.TagState
	switch state {
	case TagReconciliationRequired:
		state = "tag reconciliation required"
	case TagReconciliationUnknown:
		state = "tag reconciliation state unknown"
	}
	if e.CommitState == MutationCommitUnknown {
		return fmt.Sprintf(
			"%s: mutation outcome unknown for %q (pre-version %d, observed version %d); %s",
			e.Provider,
			e.Key,
			e.PreVersion,
			e.ObservedVersion,
			state,
		)
	}
	return fmt.Sprintf(
		"%s: value committed for %q at version %d (observed version %d); %s",
		e.Provider,
		e.Key,
		e.Version,
		e.ObservedVersion,
		state,
	)
}

func (e *PartialCommitError) Unwrap() error { return ErrPartialCommit }
