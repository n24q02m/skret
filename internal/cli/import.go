package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/n24q02m/skret/internal/importer"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/spf13/cobra"
)

func newImportCmd() *cobra.Command {
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
	)

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import secrets from external sources (dotenv, doppler, infisical)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, p, err := loadProvider()
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
					return fmt.Errorf("import: DOPPLER_TOKEN env var required")
				}
				imp = importer.NewDoppler(token, dopplerProject, dopplerConfig, "")
			case "infisical":
				token := os.Getenv("INFISICAL_TOKEN")
				if token == "" {
					return fmt.Errorf("import: INFISICAL_TOKEN env var required")
				}
				imp = importer.NewInfisical(token, infisicalProjID, infisicalEnv, infisicalURL)
			default:
				return fmt.Errorf("import: unknown source %q (use dotenv, doppler, or infisical)", from)
			}

			ctx := context.Background()
			secrets, err := imp.Import(ctx)
			if err != nil {
				return fmt.Errorf("import: %w", err)
			}

			var imported, skipped int
			for _, s := range secrets {
				if dryRun {
					cmd.Printf("[dry-run] would import %s\n", s.Key)
					imported++
					continue
				}

				if onConflict == "skip" {
					if _, err := p.Get(ctx, s.Key); err == nil {
						skipped++
						continue
					}
				}

				if err := p.Set(ctx, s.Key, s.Value, provider.SecretMeta{}); err != nil {
					return fmt.Errorf("import: set %q: %w", s.Key, err)
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
	cmd.Flags().StringVar(&onConflict, "on-conflict", "overwrite", "conflict strategy (overwrite, skip)")

	return cmd
}
