package syncer

import (
	"context"
	"fmt"
	"strings"

	"github.com/n24q02m/skret/internal/provider"
)

// Syncer pushes secrets to an external target.
type Syncer interface {
	Name() string
	Sync(ctx context.Context, secrets []*provider.Secret) error
}

// ExistingLister is implemented by syncers whose target can enumerate the
// names it already holds. Values at these targets are write-only; names are
// enough to make a sync non-destructive.
type ExistingLister interface {
	ExistingKeys(ctx context.Context) ([]string, error)
}

// FilterAbsent returns only the secrets whose target-side name (SecretName)
// is not already present on s, plus how many were skipped. It errors when
// the target cannot enumerate existing names -- callers must treat that as
// fatal rather than silently overwriting.
func FilterAbsent(ctx context.Context, s Syncer, secrets []*provider.Secret) ([]*provider.Secret, int, error) {
	l, ok := s.(ExistingLister)
	if !ok {
		return nil, 0, fmt.Errorf("no-overwrite: target %q cannot enumerate existing secrets", s.Name())
	}
	names, err := l.ExistingKeys(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("no-overwrite: list existing on %q: %w", s.Name(), err)
	}
	existing := make(map[string]bool, len(names))
	for _, n := range names {
		existing[strings.ToUpper(n)] = true
	}
	kept := make([]*provider.Secret, 0, len(secrets))
	for _, sec := range secrets {
		if existing[strings.ToUpper(SecretName(sec.Key))] {
			continue
		}
		kept = append(kept, sec)
	}
	return kept, len(secrets) - len(kept), nil
}
