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

// PerKeySyncer is an optional target capability for destinations where one
// provider request writes exactly one secret. Callers that need durable
// acknowledgement may use SyncKey to journal each provider response before
// attempting the next key. Targets whose API is whole-file or whole-patch
// (for example dotenv and Cloudflare Pages) intentionally do not implement
// this interface.
type PerKeySyncer interface {
	Syncer
	SyncKey(ctx context.Context, secret *provider.Secret) error
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

// ValidateDestinationMapping rejects ambiguous many-to-one mappings before a
// target can perform any provider I/O. GitHub Actions and Cloudflare store
// secrets by the final source-key segment, so distinct full keys must never
// acknowledge the same destination name.
func ValidateDestinationMapping(target string, secrets []*provider.Secret) error {
	if target != "github" && target != "cloudflare" {
		return nil
	}
	nameToKey := make(map[string]string, len(secrets))
	for _, secret := range secrets {
		if secret == nil {
			return fmt.Errorf("%s: secret is nil", target)
		}
		name := SecretName(secret.Key)
		if previous, ok := nameToKey[name]; ok && previous != secret.Key {
			return fmt.Errorf(
				"%s: destination name %q is produced by distinct source keys %q and %q",
				target,
				name,
				previous,
				secret.Key,
			)
		}
		nameToKey[name] = secret.Key
	}
	return nil
}
