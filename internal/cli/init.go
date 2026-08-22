package cli

import (
	"bytes"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"

	"github.com/n24q02m/skret/internal/config"
	"github.com/spf13/cobra"
)

// initOptions holds the flag values for the init command.
type initOptions struct {
	provider     string
	path         string
	region       string
	file         string
	force        bool
	dryRun       bool
	beforeCommit func() error
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
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "show the proposed config change without writing")

	return cmd
}

// run executes the init command logic.
func (o *initOptions) run(cmd *cobra.Command) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("init: get working directory: %w", err)
	}

	cfgPath := filepath.Join(cwd, config.ConfigFileName)
	existingData, readErr := os.ReadFile(cfgPath)
	exists := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("init: read existing config: %w", readErr)
	}

	cfg := defaultInitConfig()
	if exists && !o.force {
		loaded, err := config.Load(cfgPath)
		if err != nil {
			return fmt.Errorf("init: %s already exists and could not be merged (use --force to overwrite): %w", config.ConfigFileName, err)
		}
		cfg = *loaded
	}

	providerChanged := initFlagChanged(cmd, "provider", o.provider)
	pathChanged := initFlagChanged(cmd, "path", o.path)
	regionChanged := initFlagChanged(cmd, "region", o.region)
	fileChanged := initFlagChanged(cmd, "file", o.file)
	configChanged := o.force || providerChanged || pathChanged || regionChanged || fileChanged
	if exists && !providerChanged {
		envName := cfg.DefaultEnv
		if envName == "" {
			envName = "prod"
		}
		if env, ok := cfg.Environments[envName]; ok && env.Provider != "" {
			o.provider = env.Provider
		}
	}

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

	if configChanged {
		prod, ok := cfg.Environments["prod"]
		if !ok || prod.Provider == "" {
			prod = defaultInitConfig().Environments["prod"]
		}
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
		if cfg.Environments == nil {
			cfg.Environments = map[string]config.Environment{}
		}
		cfg.Environments["prod"] = prod
	}

	var data []byte
	if exists && !configChanged {
		data = existingData
	} else {
		data, err = yaml.Marshal(&cfg)
		if err != nil {
			return fmt.Errorf("init: marshal config: %w", err)
		}
	}

	if o.dryRun {
		printConfigDiff(cmd, cfgPath, existingData, data)
		return nil
	}

	if o.beforeCommit != nil {
		if err := o.beforeCommit(); err != nil {
			return err
		}
	}

	if exists && bytes.Equal(existingData, data) {
		cmd.PrintErrf("%s unchanged\n", config.ConfigFileName)
		return nil
	}

	if err := writeConfigAtomically(cfgPath, data, existingData, exists); err != nil {
		return fmt.Errorf("init: write config: %w", err)
	}

	// Update .gitignore
	gitignorePath := filepath.Join(cwd, ".gitignore")
	if err := appendGitignore(gitignorePath); err != nil {
		cmd.PrintErrf("Warning: could not update .gitignore: %v\n", err)
	}

	if exists {
		cmd.PrintErrf("Created/updated %s\n", config.ConfigFileName)
	} else {
		cmd.PrintErrf("Created %s\n", config.ConfigFileName)
	}
	return nil
}

func defaultInitConfig() config.Config {
	return config.Config{
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
}

func initFlagChanged(cmd *cobra.Command, name, value string) bool {
	if cmd != nil {
		if flag := cmd.Flags().Lookup(name); flag != nil {
			return flag.Changed
		}
	}
	return value != ""
}

func printConfigDiff(cmd *cobra.Command, path string, before, after []byte) {
	if bytes.Equal(before, after) {
		cmd.PrintErrf("dry-run: %s unchanged\n", path)
		return
	}
	cmd.PrintErrf("dry-run: %s would be updated\n--- current %s ---\n%s+++ proposed %s ---\n%s",
		path, path, before, path, after)
}

func writeBackupAtomically(path string, data []byte) error {
	backupPath := path + ".bak"
	if err := rejectBackupSymlink(backupPath); err != nil {
		return err
	}

	tmpPath, err := writeTempConfig(filepath.Dir(path), "."+filepath.Base(backupPath)+".tmp-*", data)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)

	if err := os.Rename(tmpPath, backupPath); err == nil {
		return nil
	}
	if err := rejectBackupSymlink(backupPath); err != nil {
		return err
	}
	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("replace backup: %w", err)
	}
	if err := os.Rename(tmpPath, backupPath); err != nil {
		return fmt.Errorf("replace backup: %w", err)
	}
	return nil
}

func rejectBackupSymlink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect backup: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("backup path %q is a symlink", path)
	}
	return nil
}

func writeTempConfig(dir, pattern string, data []byte) (string, error) {
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("create temporary config: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}

	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return "", fmt.Errorf("chmod temporary config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return "", fmt.Errorf("write temporary config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", fmt.Errorf("sync temporary config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("close temporary config: %w", err)
	}
	return tmpPath, nil
}

func writeConfigAtomically(path string, data, existing []byte, exists bool) error {
	if exists {
		if err := writeBackupAtomically(path, existing); err != nil {
			return fmt.Errorf("backup existing config: %w", err)
		}
	}

	tmpPath, err := writeTempConfig(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*", data)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
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
