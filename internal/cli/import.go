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
			return nil, skret.NewError(skret.ExitConfigError, "import: DOPPLER_TOKEN env var or `skret auth login doppler` required", nil)
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
			return nil, skret.NewError(skret.ExitConfigError, "import: INFISICAL_TOKEN env var or `skret auth login infisical` required", nil)
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

	orderedKeys, dedupedMap, skipped := o.deduplicate(cmd, secrets)
	existing, listLoaded := o.loadExisting(ctx, p, o.toPath, orderedKeys)

	var toImport []*provider.Secret
	var imported int
	for _, destKey := range orderedKeys {
		val := dedupedMap[destKey]

		if o.dryRun {
			cmd.PrintErrf("[dry-run] would import %s\n", destKey)
			imported++
			continue
		}

		if o.onConflict == "skip" || o.onConflict == "fail" {
			hasConflict := false
			if listLoaded {
				_, hasConflict = existing[destKey]
			} else {
				// Fallback to individual Get if both List and GetBatch failed
				if _, err := p.Get(ctx, destKey); err == nil {
					hasConflict = true
				}
			}

			if hasConflict {
				if o.onConflict == "skip" {
					skipped++
					continue
				}
				return skret.NewError(skret.ExitConflictError, fmt.Sprintf("import: conflict on %q", destKey), nil)
			}
		}

		toImport = append(toImport, &provider.Secret{
			Key:   destKey,
			Value: val,
		})
		imported++
	}

	if len(toImport) > 0 {
		if err := p.SetBatch(ctx, toImport); err != nil {
			return skret.NewError(skret.ExitProviderError, "import: set batch failed", err)
		}
	}

	cmd.PrintErrf("Imported: %d, Skipped: %d (from %s)\n", imported, skipped, imp.Name())
	return nil
}

// deduplicate processes imported secrets: applies path prefixing, skips empty values,
// and deduplicates by destination key (last value wins).
func (o *importOptions) deduplicate(cmd *cobra.Command, secrets []importer.ImportedSecret) ([]string, map[string]string, int) {
	prefix := o.toPath
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	var skipped int
	dedupedMap := make(map[string]string, len(secrets))
	orderedKeys := make([]string, 0, len(secrets))

	for _, s := range secrets {
		destKey := s.Key
		if prefix != "" {
			destKey = prefix + strings.TrimPrefix(destKey, "/")
		}

		if s.Value == "" {
			cmd.PrintErrf("skipping empty value for %s\n", destKey)
			skipped++
			continue
		}

		if _, ok := dedupedMap[destKey]; !ok {
			orderedKeys = append(orderedKeys, destKey)
		}
		dedupedMap[destKey] = s.Value
	}

	return orderedKeys, dedupedMap, skipped
}

// loadExisting attempts to fetch existing secrets from the provider using List
// with a fallback to GetBatch for efficiency.
func (o *importOptions) loadExisting(ctx context.Context, p provider.SecretProvider, prefix string, orderedKeys []string) (map[string]struct{}, bool) {
	existing := make(map[string]struct{})
	if o.dryRun || (o.onConflict != "skip" && o.onConflict != "fail") {
		return existing, false
	}

	// Ensure prefix ends with a slash for List if it's meant to be a path
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	exList, err := p.List(ctx, prefix)
	if err == nil {
		for _, s := range exList {
			existing[s.Key] = struct{}{}
		}
		return existing, true
	}

	if len(orderedKeys) > 0 {
		// If List fails, try GetBatch as a more efficient fallback than individual Gets
		exBatch, bErr := p.GetBatch(ctx, orderedKeys)
		if bErr == nil {
			for _, s := range exBatch {
				existing[s.Key] = struct{}{}
			}
			return existing, true
		}
	}

	return existing, false
}
