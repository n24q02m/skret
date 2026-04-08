package syncer

import (
	"context"

	"github.com/n24q02m/skret/internal/provider"
)

// Syncer pushes secrets to an external target.
type Syncer interface {
	Name() string
	Sync(ctx context.Context, secrets []*provider.Secret) error
}
