package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ErrConfigNotFound is returned when .skret.yaml cannot be found.
var ErrConfigNotFound = errors.New("config: .skret.yaml not found")

// ConfigFileName is the expected config file name.
const ConfigFileName = ".skret.yaml"

// Load reads and validates a .skret.yaml from the given path.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: resolve path %q: %w", path, err)
	}

	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", abs, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %q: %w", abs, err)
	}

	cfg.ConfigDir = filepath.Dir(abs)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Discover walks from startDir upward to find .skret.yaml, stopping at git root or filesystem root.
func Discover(startDir string) (string, error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", fmt.Errorf("config: resolve path: %w", err)
	}

	for {
		candidate := filepath.Join(dir, ConfigFileName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}

		// Stop at git root (even if no .skret.yaml found there)
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return "", ErrConfigNotFound
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", ErrConfigNotFound
		}
		dir = parent
	}
}
