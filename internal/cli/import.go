package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/n24q02m/skret/internal/importer"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

func newImportCmd(opts *GlobalOpts) *cobra.Command {
	var (
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
	)

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import secrets from external sources (dotenv, doppler, infisical)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, p, err := loadProvider(opts)
			if err != nil {
				return err
			}
			defer p.Close()

			var imp importer.Importer
			switch from {
			case "dotenv":
				if file == "" {
					file = ".env"
				}
				imp = importer.NewDotenv(file)
			case "doppler":
				token := os.Getenv("DOPPLER_TOKEN")
				if token == "" {
					return skret.NewError(skret.ExitConfigError, "import: DOPPLER_TOKEN env var required", nil)
				}
				imp = importer.NewDoppler(token, dopplerProject, dopplerConfig, "")
			case "infisical":
				token := os.Getenv("INFISICAL_TOKEN")
				if token == "" {
					return skret.NewError(skret.ExitConfigError, "import: INFISICAL_TOKEN env var required", nil)
				}
				imp = importer.NewInfisical(token, infisicalProjID, infisicalEnv, infisicalURL)
			default:
				return skret.NewError(skret.ExitConfigError, fmt.Sprintf("import: unknown source %q", from), nil)
			}

			ctx := context.Background()
			secrets, err := imp.Import(ctx)
			if err != nil {
				return skret.NewError(skret.ExitNetworkError, "import failed", err)
			}

			// Ensure toPath ends with a slash if provided and secrets don't start with one
			prefix := toPath
			if prefix != "" && !strings.HasSuffix(prefix, "/") {
				prefix += "/"
			}

			var imported, skipped int
			for _, s := range secrets {
				key := s.Key
				if prefix != "" {
					key = prefix + strings.TrimPrefix(key, "/")
				}

				if dryRun {
					cmd.Printf("[dry-run] would import %s\n", key)
					imported++
					continue
				}

				if onConflict == "skip" {
					if _, err := p.Get(ctx, key); err == nil {
						skipped++
						continue
					}
				} else if onConflict == "fail" {
					if _, err := p.Get(ctx, key); err == nil {
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
		},
	}

	cmd.Flags().StringVar(&from, "from", "dotenv", "import source (dotenv, doppler, infisical)")
	cmd.Flags().StringVar(&file, "file", "", "source file path (for dotenv)")
	cmd.Flags().StringVar(&dopplerProject, "doppler-project", "", "Doppler project name")
	cmd.Flags().StringVar(&dopplerConfig, "doppler-config", "", "Doppler config name")
	cmd.Flags().StringVar(&infisicalProjID, "infisical-project-id", "", "Infisical project ID")
	cmd.Flags().StringVar(&infisicalEnv, "infisical-env", "", "Infisical environment")
	cmd.Flags().StringVar(&infisicalURL, "infisical-url", "", "Infisical API base URL")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview without writing")
	cmd.Flags().StringVar(&onConflict, "on-conflict", "skip", "conflict strategy (overwrite, skip, fail)")
	cmd.Flags().StringVar(&toPath, "to-path", "", "destination path prefix for imported secrets")

	return cmd
}
