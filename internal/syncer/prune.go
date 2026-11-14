package syncer

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/n24q02m/skret/internal/provider"
)

// ErrPruneEmptySource is returned when prune is asked to reconcile a target
// against an empty source set. An empty listing is far more likely to be a
// wrong path, a wrong environment or a provider fault than a real intent to
// wipe the target, so prune refuses instead of deleting everything.
var ErrPruneEmptySource = errors.New("prune: refusing to prune against an empty source set")

// TargetSecret is the metadata a target returns for one stored secret. It
// never carries a value: GitHub Actions secrets are write-only.
type TargetSecret struct {
	Name      string
	UpdatedAt string
}

// Pruner is implemented by targets that can enumerate their stored secrets
// with metadata and delete one by name.
type Pruner interface {
	ExistingSecrets(ctx context.Context) ([]TargetSecret, error)
	DeleteSecret(ctx context.Context, name string) error
}

// CanPrune reports whether s supports Orphans and Prune.
func CanPrune(s Syncer) bool {
	_, ok := s.(Pruner)
	return ok
}

func asPruner(s Syncer) (Pruner, error) {
	p, ok := s.(Pruner)
	if !ok {
		return nil, fmt.Errorf("prune: target %q cannot delete secrets", s.Name())
	}
	return p, nil
}

// Orphans lists the secrets stored on s whose name is not produced by any
// source key, sorted by name. Source keys map through SecretName (the name
// Sync writes under) and compare case-insensitively, like FilterAbsent.
// Orphans only reads the target.
func Orphans(ctx context.Context, s Syncer, source []*provider.Secret) ([]TargetSecret, error) {
	p, err := asPruner(s)
	if err != nil {
		return nil, err
	}
	if len(source) == 0 {
		return nil, ErrPruneEmptySource
	}
	stored, err := p.ExistingSecrets(ctx)
	if err != nil {
		return nil, fmt.Errorf("prune: list existing on %q: %w", s.Name(), err)
	}
	wanted := make(map[string]bool, len(source))
	for _, sec := range source {
		wanted[strings.ToUpper(SecretName(sec.Key))] = true
	}
	var orphans []TargetSecret
	for _, ts := range stored {
		if !wanted[strings.ToUpper(ts.Name)] {
			orphans = append(orphans, ts)
		}
	}
	sort.Slice(orphans, func(i, j int) bool { return orphans[i].Name < orphans[j].Name })
	return orphans, nil
}

// Prune deletes each orphan from s in order, one request per name, and stops
// at the first failure. It returns how many deletes the target acknowledged.
func Prune(ctx context.Context, s Syncer, orphans []TargetSecret) (int, error) {
	p, err := asPruner(s)
	if err != nil {
		return 0, err
	}
	for i, ts := range orphans {
		if err := p.DeleteSecret(ctx, ts.Name); err != nil {
			return i, err
		}
	}
	return len(orphans), nil
}
