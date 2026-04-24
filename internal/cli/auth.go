package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage authentication for secret providers",
	}

	cmd.AddCommand(newAuthLoginCmd())
	cmd.AddCommand(newAuthStatusCmd())
	cmd.AddCommand(newAuthLogoutCmd())

	return cmd
}

func newAuthLoginCmd() *cobra.Command {
	var (
		method  string
		rawOpts []string
	)

	cmd := &cobra.Command{
		Use:   "login <provider>",
		Short: "Authenticate with a secret provider (aws, doppler, infisical)",
		Long: "Authenticate with a secret provider.\n\n" +
			"Pass method-specific values via repeated --opt key=value (e.g. --opt token=dp.pt.xxx,\n" +
			"--opt profile=dev, --opt role_arn=arn:aws:iam::..., --opt client_id=..., --opt client_secret=...).\n" +
			"Token methods also accept DOPPLER_TOKEN / INFISICAL_TOKEN env vars as fallback.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := args[0]
			opts := map[string]string{}
			if method != "" {
				opts["method"] = method
			}
			for _, kv := range rawOpts {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					return skret.NewError(skret.ExitConfigError, fmt.Sprintf("--opt must be key=value, got %q", kv), nil)
				}
				opts[k] = v
			}

			ctx := context.Background()
			if err := auth.Login(ctx, provider, opts); err != nil {
				return skret.NewError(skret.ExitConfigError, fmt.Sprintf("auth login %s failed", provider), err)
			}

			cmd.Printf("Successfully authenticated with %s\n", provider)
			return nil
		},
	}

	cmd.Flags().StringVar(&method, "method", "", "authentication method (e.g., sso, access-key, oauth, browser)")
	cmd.Flags().StringArrayVar(&rawOpts, "opt", nil, "method-specific option key=value (repeatable)")

	return cmd
}

func newAuthStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show authentication status for all providers",
		RunE: func(cmd *cobra.Command, _ []string) error {
			store := auth.NewStore()
			providers := []string{"aws", "doppler", "infisical"}

			ctx := context.Background()
			for _, p := range providers {
				cred, err := store.Load(p)
				if err != nil {
					cmd.Printf("  %-12s not configured\n", p)
					continue
				}

				status := "valid"
				if cred.IsExpired() {
					status = "expired"
				}

				// Try to validate if provider is registered
				if _, resolveErr := auth.Resolve(ctx, p); resolveErr != nil {
					status = "invalid"
				}

				cmd.Printf("  %-12s %s (method: %s)\n", p, status, cred.Method)
			}

			return nil
		},
	}
}

func newAuthLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout <provider>",
		Short: "Remove stored credentials for a provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := args[0]
			store := auth.NewStore()

			if err := store.Delete(provider); err != nil {
				return skret.NewError(skret.ExitGenericError, fmt.Sprintf("auth logout %s failed", provider), err)
			}

			cmd.Printf("Logged out from %s\n", provider)
			return nil
		},
	}
}
