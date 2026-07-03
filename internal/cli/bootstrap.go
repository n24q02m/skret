package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/n24q02m/skret/internal/auth"
	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

// newBootstrapClients builds the IAM/STS clients from the bootstrap (admin)
// identity. Seam for tests. Credential source, in order:
//  1. --profile <name>           -> the named shared-config profile
//  2. interactive stdin (Case 1) -> paste admin/root keys directly through skret
//     (used in-memory only, never stored)
//  3. non-interactive fallback   -> the default credential chain (env/instance),
//     for CI where keys come from the environment
var newBootstrapClients = func(ctx context.Context, profile, region string) (auth.IAMClient, auth.STSClient, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	switch {
	case profile != "":
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	case isInteractiveStdin():
		creds, err := auth.PromptBootstrapCredentials(ctx, os.Stdin)
		if err != nil {
			return nil, nil, err
		}
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken),
		))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, nil, err
	}
	return iam.NewFromConfig(cfg), sts.NewFromConfig(cfg), nil
}

// bootstrapStore returns the credential store. Seam for tests.
var bootstrapStore = auth.NewStore

// isInteractiveStdin reports whether stdin is a terminal. Seam for tests.
var isInteractiveStdin = auth.IsInteractiveStdin

func newBootstrapCmd(opts *GlobalOpts) *cobra.Command {
	var (
		project, path, region, userName, profile string
		printOnly, force, yes                    bool
	)
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Provision a dedicated least-privilege skret key from an admin/root identity",
		Long: "Provisions a dedicated least-privilege IAM user and access key from an admin/root " +
			"AWS identity. The admin credentials are used only during bootstrap (never stored locally). " +
			"The created skret user key is stored in the credential cache for future use.",
		Example: "  skret bootstrap --path=/myapp/prod --region=ap-southeast-1",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Resolve path/region/profile/project: explicit flags win, else fall
			// back to the resolved config. A provider is deliberately NOT built —
			// the skret user may not exist yet, so we only need the config values.
			if path == "" || region == "" || profile == "" {
				if resolved, err := resolveBootstrapConfig(opts); err == nil {
					if path == "" {
						path = resolved.Path
					}
					if region == "" {
						region = resolved.Region
					}
					if profile == "" {
						profile = resolved.Profile
					}
				}
			}
			if path == "" {
				return skret.NewError(skret.ExitValidationError,
					"bootstrap: no SSM path to scope to; pass --path=/namespace/env or run from a repo with a .skret.yaml", nil)
			}
			if project == "" {
				project = sanitizeProject(path)
			}

			user := userName
			if user == "" {
				user = "skret-" + project
			}

			if !force {
				if existing, err := bootstrapStore().Load("aws"); err == nil && existing.Method == "access-key" {
					cmd.PrintErrln("An aws access-key credential is already stored. Re-run with --force to provision a new one.")
					return nil
				}
			}

			if !yes {
				if !isInteractiveStdin() {
					return skret.NewError(skret.ExitValidationError,
						"bootstrap will create an IAM user and key; re-run with --yes to confirm in non-interactive mode", nil)
				}
				prompt := fmt.Sprintf("About to create IAM user %q with a policy scoped to SSM path %q (region %s). Continue?",
					user, path, region)
				if !auth.Confirm(os.Stdin, cmd.OutOrStdout(), prompt) {
					return nil
				}
			}

			iamc, stsc, err := newBootstrapClients(cmd.Context(), profile, region)
			if err != nil {
				return skret.NewError(skret.ExitAuthError, "bootstrap: load admin credentials failed", err)
			}
			flow := &auth.BootstrapFlow{IAM: iamc, STS: stsc}
			res, err := flow.Provision(cmd.Context(), auth.BootstrapOpts{
				Project: project, Path: path, Region: region, UserName: userName,
			})
			if err != nil {
				return skret.NewError(skret.ExitProviderError, "bootstrap failed", err)
			}

			if !printOnly {
				if err := bootstrapStore().Save(&auth.Credential{
					Provider: "aws", Method: "access-key", Token: res.SecretKey,
					Metadata: map[string]string{"access_key_id": res.AccessKeyID},
				}); err != nil {
					return skret.NewError(skret.ExitConfigError, "bootstrap: store credential failed", err)
				}
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "\nCreated IAM user %s in account %s\nPolicy %s scoped to %s\nAccess Key ID: %s\n",
				res.UserName, res.Account, res.PolicyName, path, res.AccessKeyID)
			if printOnly {
				fmt.Fprintf(out, "\nSecret Access Key (shown once, give to the user; not stored locally):\n  %s\n", res.SecretKey)
			} else {
				fmt.Fprintf(out, "\nStored locally. Secret Access Key (shown once — save it to set up another machine with `skret auth login aws`):\n  %s\n", res.SecretKey)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "project name (-> IAM user skret-<project> and default scope)")
	cmd.Flags().StringVar(&path, "path", "", "SSM path to scope to (default: env path from .skret.yaml)")
	cmd.Flags().StringVar(&region, "region", "", "AWS region (default: config/env)")
	cmd.Flags().StringVar(&userName, "user-name", "", "override IAM user name (default skret-<project>)")
	cmd.Flags().StringVar(&profile, "profile", "", "AWS profile to use as the bootstrap identity (default: paste admin/root keys interactively)")
	cmd.Flags().BoolVar(&printOnly, "print-only", false, "print the key instead of storing it (provision for another person/machine)")
	cmd.Flags().BoolVar(&force, "force", false, "provision even if an aws credential is already stored")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt")
	return cmd
}

// resolveBootstrapConfig resolves config the same way loadProvider does, but
// stops before building a provider: bootstrap only needs the env's path/region/
// profile, and the skret user it provisions may not exist yet.
func resolveBootstrapConfig(opts *GlobalOpts) (*config.ResolvedConfig, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	resolveOpts := config.ResolveOpts{
		Env:      opts.Env,
		Provider: opts.Provider,
		Path:     opts.Path,
		Region:   opts.Region,
		Profile:  opts.Profile,
		File:     opts.File,
	}
	cfgPath, derr := config.Discover(cwd)
	if derr != nil {
		// No .skret.yaml: nothing to resolve. The command's own --path/--region
		// flags are the input in that case.
		return nil, derr
	}
	cfg, lerr := config.Load(cfgPath)
	if lerr != nil {
		return nil, lerr
	}
	return config.Resolve(cfg, resolveOpts)
}

// sanitizeProject derives a default project name from the SSM path's last
// non-empty segment (e.g. /myapp/prod -> prod). Only [a-zA-Z0-9_-] is kept so
// the result is a valid IAM user/policy name suffix.
func sanitizeProject(path string) string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	last := segs[len(segs)-1]
	var b strings.Builder
	for _, r := range last {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return filepath.Base(path)
	}
	return b.String()
}
