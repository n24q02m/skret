package cli

import (
	"errors"
	"fmt"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
)

// wrapProviderMutationError preserves the provider's non-secret partial state
// so set/import callers cannot report an ambiguous write as if nothing changed.
func wrapProviderMutationError(operation, key string, err error) error {
	var partial *provider.PartialCommitError
	if errors.As(err, &partial) {
		message := fmt.Sprintf(
			"%s %q partially committed; reconcile provider metadata before retry (committed version %d, observed version %d, tag state %s)",
			operation,
			key,
			partial.Version,
			partial.ObservedVersion,
			partial.TagState,
		)
		return skret.NewError(skret.ExitProviderError, message, partial)
	}
	return skret.NewError(skret.ExitProviderError, fmt.Sprintf("%s %q", operation, key), err)
}
