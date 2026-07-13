package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/n24q02m/skret/internal/config"
)

// initOptions holds the flag values for the init command.
type initOptions struct {
	provider string
	path     string
	region   string
	file     string
	force    bool
}

// newInitCmd creates a new init command.
func newInitCmd() *cobra.Command {
	opts := &initOptions{}

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize .skret.yaml in the current directory",
		Long: "Creates a .skret.yaml configuration file in the current directory with the specified " +
			"provider settings. Automatically updates .gitignore to exclude secret files " +
			"(.secrets.*.yaml and .secrets.*.yml).",
		Example: `  skret init --provider=aws --path=/myapp/prod --region=ap-southeast-1
  skret init --provider=local --file=./.secrets.dev.yaml`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return opts.run(cmd)
		},
	}

	cmd.Flags().StringVar(&opts.provider, "provider", "", "secret provider (aws, local); prod env keeps its /myapp/prod, us-east-1 defaults when unset")
	cmd.Flags().StringVar(&opts.path, "path", "", "secret path prefix (aws provider)")
	cmd.Flags().StringVar(&opts.region, "region", "", "cloud region (aws provider)")
	cmd.Flags().StringVar(&opts.file, "file", "", "local file path (local provider)")
	cmd.Flags().BoolVar(&opts.force, "force", false, "overwrite existing .skret.yaml")

	return cmd
}

// run executes the init command logic.
func (o *initOptions) run(cmd *cobra.Command) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("init: get working directory: %w", err)
	}

	cfgPath := filepath.Join(cwd, config.ConfigFileName)

	if !o.force {
		if _, err := os.Stat(cfgPath); err == nil {
			return fmt.Errorf("init: %s already exists (use --force to overwrite)", config.ConfigFileName)
		}
	}

	cfg := config.Config{
		Version:    "1",
		DefaultEnv: "dev",
		Environments: map[string]config.Environment{
			"dev": {
				Provider: "local",
				File:     ".secrets.dev.yaml",
			},
			"prod": {
				Provider: "aws",
				Path:     "/myapp/prod",
				Region:   "us-east-1",
			},
		},
	}

	// Override the baked-in prod entry ONLY for the flags the user actually
	// passed (cmd.Flags().Changed, per flag) -- otherwise the good defaults
	// set above (Path: "/myapp/prod", Region: "us-east-1") must survive a
	// bare `skret init` untouched (fix for audit finding C1 root cause 1:
	// this used to be gated on `o.provider != ""`, which was ALWAYS true
	// because --provider had a non-empty "aws" default, so bare init always
	// wiped the good defaults with the flags' zero values).
	providerChanged := cmd.Flags().Changed("provider")
	pathChanged := cmd.Flags().Changed("path")
	regionChanged := cmd.Flags().Changed("region")
	fileChanged := cmd.Flags().Changed("file")

	if providerChanged {
		reg := defaultRegistry()
		known := false
		for _, name := range reg.Providers() {
			if name == o.provider {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("init: unknown provider %q (available: %v)", o.provider, reg.Providers())
		}
	}

	if providerChanged || pathChanged || regionChanged || fileChanged {
		prod := cfg.Environments["prod"]
		if providerChanged {
			prod.Provider = o.provider
		}
		if pathChanged {
			prod.Path = o.path
		}
		if regionChanged {
			prod.Region = o.region
		}
		if fileChanged {
			prod.File = o.file
		}
		if prod.Provider == "local" && prod.File == "" {
			prod.File = ".secrets.prod.yaml"
		}
		cfg.Environments["prod"] = prod
	}

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("init: marshal config: %w", err)
	}

	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		return fmt.Errorf("init: write config: %w", err)
	}

	// Update .gitignore
	gitignorePath := filepath.Join(cwd, ".gitignore")
	if err := appendGitignore(gitignorePath); err != nil {
		cmd.PrintErrf("Warning: could not update .gitignore: %v\n", err)
	}

	cmd.PrintErrf("Created %s\n", config.ConfigFileName)
	return nil
}

func appendGitignore(path string) error {
	entries := []string{".secrets.*.yaml", ".secrets.*.yml"}

	existing, _ := os.ReadFile(path)
	content := string(existing)

	var toAdd []string
	for _, entry := range entries {
		if !strings.Contains(content, entry) {
			toAdd = append(toAdd, entry)
		}
	}

	if len(toAdd) == 0 {
		return nil
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	if content != "" && !strings.HasSuffix(content, "\n") {
		if _, err := f.WriteString("\n"); err != nil {
			return err
		}
	}

	if _, err := f.WriteString("\n# skret local provider files\n"); err != nil {
		return err
	}
	for _, entry := range toAdd {
		if _, err := f.WriteString(entry + "\n"); err != nil {
			return err
		}
	}
	return nil
}
