package cli

import (
	"context"
	"strings"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

// setupAuthHook authenticates a provider; it is auth.Login in production and
// is overridable in tests.
var setupAuthHook = func(provider, method string, opts map[string]string) error {
	o := map[string]string{}
	for k, v := range opts {
		o[k] = v
	}
	if method != "" {
		o["method"] = method
	}
	return auth.Login(context.Background(), provider, o)
}

func newSetupCmd() *cobra.Command {
	io := &initOptions{}
	var (
		method string
		rawOpt []string
		yes    bool
	)
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Initialize .skret.yaml and authenticate in one step",
		Long: "Creates .skret.yaml (like 'skret init') then authenticates the " +
			"provider (like 'skret auth login'), matching the Doppler/Infisical " +
			"setup -> run loop.",
		Example: "  skret setup",
		RunE: func(cmd *cobra.Command, _ []string) error {
			io.force = true // setup is idempotent; overwriting is expected
			if err := io.run(cmd); err != nil {
				return err
			}
			if io.provider == "local" {
				cmd.PrintErrln("Local provider: no authentication needed. Next: skret run -- <cmd>")
				return nil
			}
			// Authenticating a non-local provider goes through a genuinely
			// interactive step (AWS SSO device-code browser flow, or pasted
			// access keys read from stdin -- see auth.Method.Interactive for
			// aws's "sso"/"access-key" methods). Without a terminal to drive
			// that, fail fast with an actionable message instead of hanging
			// or failing deep inside the auth package (mirrors bootstrap.go's
			// existing --yes/isInteractiveStdin gate). --yes = "I know this
			// may be interactive, proceed anyway" (fix for audit finding I4:
			// --yes used to be declared and documented but never read).
			if !yes && !isInteractiveStdin() {
				return skret.NewError(skret.ExitValidationError,
					"setup: authenticating "+io.provider+" needs an interactive step (browser SSO or pasted keys); "+
						"re-run with --yes to attempt it anyway, or run 'skret auth login "+io.provider+
						" --method=profile' (or --method=assume-role) for a non-interactive method", nil)
			}
			opts := map[string]string{}
			for _, kv := range rawOpt {
				if i := strings.IndexByte(kv, '='); i > 0 {
					opts[kv[:i]] = kv[i+1:]
				}
			}
			if err := setupAuthHook(io.provider, method, opts); err != nil {
				return err
			}
			cmd.PrintErrln("Setup complete. Next: skret run -- <cmd>")
			return nil
		},
	}
	cmd.Flags().StringVar(&io.provider, "provider", "aws", "secret provider (aws, local)")
	cmd.Flags().StringVar(&io.path, "path", "", "secret path prefix (aws)")
	cmd.Flags().StringVar(&io.region, "region", "", "cloud region (aws)")
	cmd.Flags().StringVar(&io.file, "file", "", "local file path (local)")
	cmd.Flags().StringVar(&method, "method", "", "auth method (sso, access-key, profile)")
	cmd.Flags().StringArrayVar(&rawOpt, "opt", nil, "auth option key=value (repeatable)")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm running an interactive auth step non-interactively (required when stdin is not a terminal)")
	return cmd
}
