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

func newInitCmd() *cobra.Command {
        var (
                provider string
                path     string
                region   string
                file     string
                force    bool
        )

        cmd := &cobra.Command{
                Use:   "init",
                Short: "Initialize .skret.yaml in the current directory",
                RunE: func(cmd *cobra.Command, _ []string) error {
                        cwd, err := os.Getwd()
                        if err != nil {
                                return fmt.Errorf("init: get working directory: %w", err)
                        }

                        cfgPath := filepath.Join(cwd, config.ConfigFileName)

                        if !force {
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

                        // Override with flags if provided
                        if provider != "" {
                                cfg.Environments["prod"] = config.Environment{
                                        Provider: provider,
                                        Path:     path,
                                        Region:   region,
                                }
                                if file != "" {
                                        env := cfg.Environments["prod"]
                                        env.File = file
                                        cfg.Environments["prod"] = env
                                }
                        }

                        data, err := yaml.Marshal(&cfg)
                        if err != nil {
                                return fmt.Errorf("init: marshal config: %w", err)
                        }

                        if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
                                return fmt.Errorf("init: write config: %w", err)
                        }

                        // Update .gitignore
                        gitignorePath := filepath.Join(cwd, ".gitignore")
                        if err := appendGitignore(gitignorePath); err != nil {
                                cmd.PrintErrf("Warning: could not update .gitignore: %v\n", err)
                        }

                        cmd.Printf("Created %s\n", config.ConfigFileName)
                        return nil
                },
        }

        cmd.Flags().StringVar(&provider, "provider", "aws", "secret provider (aws, local)")
        cmd.Flags().StringVar(&path, "path", "", "secret path prefix (aws provider)")
        cmd.Flags().StringVar(&region, "region", "", "cloud region (aws provider)")
        cmd.Flags().StringVar(&file, "file", "", "local file path (local provider)")
        cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite existing .skret.yaml")

        return cmd
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

        f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
        if err != nil {
                return err
        }
        defer f.Close()

        if len(content) > 0 && !strings.HasSuffix(content, "\n") {
                f.WriteString("\n")
        }

        f.WriteString("\n# skret local provider files\n")
        for _, entry := range toAdd {
                f.WriteString(entry + "\n")
        }
        return nil
}
