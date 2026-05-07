package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/n24q02m/skret/internal/importer"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

// importOptions encapsulates the state and logic for the import command.
type importOptions struct {
	global          *GlobalOpts
	from            string
	file            string
	dopplerProject  string
	dopplerConfig   string
	infisicalProjID string
	infisicalEnv    string
	infisicalURL    string
	dryRun          bool
	onConflict      string
	toPath          string
}

// newImportCmd creates a new import command.
func newImportCmd(opts *GlobalOpts) *cobra.Command {
	o := &importOptions{global: opts}

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import secrets from external sources (dotenv, doppler, infisical)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}

	cmd.Flags().StringVar(&o.from, "from", "dotenv", "import source (dotenv, doppler, infisical)")
	cmd.Flags().StringVar(&o.file, "file", "", "source file path (for dotenv)")
	cmd.Flags().StringVar(&o.dopplerProject, "doppler-project", "", "Doppler project name")
	cmd.Flags().StringVar(&o.dopplerConfig, "doppler-config", "", "Doppler config name")
	cmd.Flags().StringVar(&o.infisicalProjID, "infisical-project-id", "", "Infisical project ID")
	cmd.Flags().StringVar(&o.infisicalEnv, "infisical-env", "", "Infisical environment")
	cmd.Flags().StringVar(&o.infisicalURL, "infisical-url", "", "Infisical API base URL")
	cmd.Flags().BoolVar(&o.dryRun, "dry-run", false, "preview without writing")
	cmd.Flags().StringVar(&o.onConflict, "on-conflict", "skip", "conflict strategy (overwrite, skip, fail)")
	cmd.Flags().StringVar(&o.toPath, "to-path", "", "destination path prefix for imported secrets")

	return cmd
}

// createImporter instantiates the appropriate importer based on the 'from' flag.
func (o *importOptions) createImporter() (importer.Importer, error) {
	switch o.from {
	case "dotenv":
		file := o.file
		if file == "" {
			file = ".env"
		}
		return importer.NewDotenv(file), nil
	case "doppler":
		token := os.Getenv("DOPPLER_TOKEN")
		if token == "" {
			if cred, err := auth.Resolve(context.Background(), "doppler"); err == nil {
				token = cred.Token
			}
		}
		if token == "" {
			return nil, skret.NewError(skret.ExitConfigError, "import: DOPPLER_TOKEN env var or `skret auth doppler` required", nil)
		}
		return importer.NewDoppler(token, o.dopplerProject, o.dopplerConfig, ""), nil
	case "infisical":
		token := os.Getenv("INFISICAL_TOKEN")
		if token == "" {
			if cred, err := auth.Resolve(context.Background(), "infisical"); err == nil {
				token = cred.Token
			}
		}
		if token == "" {
			return nil, skret.NewError(skret.ExitConfigError, "import: INFISICAL_TOKEN env var or `skret auth infisical` required", nil)
		}
		return importer.NewInfisical(token, o.infisicalProjID, o.infisicalEnv, o.infisicalURL), nil
	default:
		return nil, skret.NewError(skret.ExitConfigError, fmt.Sprintf("import: unknown source %q", o.from), nil)
	}
}

// run executes the import logic.
func (o *importOptions) run(cmd *cobra.Command) error {
	_, p, err := loadProvider(o.global)
	if err != nil {
		return err
	}
	defer p.Close()

	imp, err := o.createImporter()
	if err != nil {
		return err
	}

	ctx := context.Background()
	secrets, err := imp.Import(ctx)
	if err != nil {
		return skret.NewError(skret.ExitNetworkError, "import failed", err)
	}

	// Ensure toPath ends with a slash if provided and secrets don't start with one
	prefix := o.toPath
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	var imported, skipped int
	existing := make(map[string]struct{})
	listLoaded := false
	if !o.dryRun && (o.onConflict == "skip" || o.onConflict == "fail") {
		exList, err := p.List(ctx, prefix)
		if err == nil {
			for _, s := range exList {
				existing[s.Key] = struct{}{}
			}
			listLoaded = true
		}
	}

	for _, s := range secrets {
		key := s.Key
		if prefix != "" {
			key = prefix + strings.TrimPrefix(key, "/")
		}

		// SSM PutParameter requires Value length >= 1. Doppler exports
		// placeholder entries like DOPPLER_CONFIG="" — skip those rather than
		// failing the whole batch.
		if s.Value == "" {
			cmd.PrintErrf("skipping empty value for %s\n", key)
			skipped++
			continue
		}

		if o.dryRun {
			cmd.Printf("[dry-run] would import %s\n", key)
			imported++
			continue
		}

		if o.onConflict == "skip" || o.onConflict == "fail" {
			hasConflict := false
			if listLoaded {
				_, hasConflict = existing[key]
			} else {
				if _, err := p.Get(ctx, key); err == nil {
					hasConflict = true
				}
			}

			if hasConflict {
				if o.onConflict == "skip" {
					skipped++
					continue
				}
				return skret.NewError(skret.ExitConflictError, fmt.Sprintf("import: conflict on %q", key), nil)
			}
		}
		if err := p.Set(ctx, key, s.Value, provider.SecretMeta{}); err != nil {
			return skret.NewError(skret.ExitProviderError, fmt.Sprintf("import: set %q", key), err)
		}
		imported++
	}

	cmd.Printf("Imported: %d, Skipped: %d (from %s)\n", imported, skipped, imp.Name())
	return nil
}
