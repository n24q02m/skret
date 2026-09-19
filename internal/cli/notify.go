package cli

import (
	"context"
	"fmt"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/notify"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

// reportMutation delivers a names-only webhook notification for a completed
// mutation (see internal/notify). Fire-and-report: a delivery failure warns
// on stderr and never fails the command -- the mutation already succeeded --
// unless strict is set (--strict-notify), which turns the warning into an
// ExitNetworkError AFTER the fact, for pipelines that must know the webhook
// did not fire.
func reportMutation(cmd *cobra.Command, resolved *config.ResolvedConfig, strict bool, ev notify.Event, keyNames ...string) error {
	n := notify.FromConfig(resolved.Notify)
	if n == nil {
		return nil
	}
	if err := n.Send(context.Background(), ev, resolved.EnvName, keyNames); err != nil {
		if strict {
			return skret.NewError(skret.ExitNetworkError, fmt.Sprintf("%s: notify webhook failed (the mutation itself succeeded)", ev), err)
		}
		cmd.PrintErrf("warning: %s webhook notify failed: %v (the mutation succeeded; pass --strict-notify to make notify failure fatal)\n", ev, err)
	}
	return nil
}
