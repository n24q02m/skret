package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/n24q02m/skret/internal/auth"
	skaws "github.com/n24q02m/skret/internal/provider/aws"
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
		Short: "Authenticate with a secret provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := args[0]
			opts := map[string]string{"method": method}
			for _, o := range rawOpts {
				k, v, ok := strings.Cut(o, "=")
				if !ok {
					return fmt.Errorf("invalid option %q (expected k=v)", o)
				}
				opts[k] = v
			}

			if err := auth.Login(cmd.Context(), provider, opts); err != nil {
				return skret.NewError(skret.ExitGenericError, fmt.Sprintf("auth login %s failed", provider), err)
			}

			cmd.PrintErrf("Successfully authenticated with %s\n", provider)
			return nil
		},
	}

	cmd.Flags().StringVarP(&method, "method", "m", "", "Authentication method (e.g., sso, access-key, token)")
	cmd.Flags().StringSliceVarP(&rawOpts, "option", "o", nil, "Additional options in key=value format")

	return cmd
}

func newAuthStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show authentication status for all providers",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store := auth.NewStore()
			providers := []string{"aws", "doppler", "infisical"}

			fmt.Fprintf(cmd.OutOrStdout(), "Authentication Status:\n")
			for _, p := range providers {
				cred, err := store.Load(p)
				if err != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "  %-12s not configured\n", p)
					continue
				}

				status := getCredentialStatus(ctx, p, cred)
				fmt.Fprintf(cmd.OutOrStdout(), "  %-12s %s (method: %s)\n", p, status, cred.Method)
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

			cmd.PrintErrf("Logged out from %s\n", provider)
			return nil
		},
	}
}

// awsLivenessProbe verifies real AWS reachability using the same credential
// resolution skret uses for operations (stored credential first, else SDK
// default chain), so status never disagrees with what `skret list` does.
// Overridable in tests. It must never surface secret values.
var awsLivenessProbe = skaws.Probe

func getCredentialStatus(ctx context.Context, provider string, cred *auth.Credential) string {
	if cred.IsExpired() {
		return "expired"
	}

	// AWS: probe real reachability instead of trusting stored metadata —
	// "method: profile" used to report "valid" with no working credential.
	if provider == "aws" {
		if err := awsLivenessProbe(ctx, cred); err != nil {
			if auth.IsAuthError(err) {
				return "expired"
			}
			return "unreachable"
		}
		return "valid"
	}

	if _, err := auth.Resolve(ctx, provider); err != nil {
		return "invalid"
	}
	return "valid"
}
