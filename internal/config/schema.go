package config

import "fmt"

// Config is the root schema for .skret.yaml.
type Config struct {
	Version      string                 `yaml:"version"`
	DefaultEnv   string                 `yaml:"default_env"`
	Project      string                 `yaml:"project"`
	Environments map[string]Environment `yaml:"environments"`
	Required     []string               `yaml:"required"`
	Exclude      []string               `yaml:"exclude"`
	Sync         *SyncConfig            `yaml:"sync,omitempty"`
}

// Environment defines provider configuration for one environment.
type Environment struct {
	Provider string `yaml:"provider"`
	Path     string `yaml:"path"`
	Region   string `yaml:"region"`
	Profile  string `yaml:"profile"`
	KMSKeyID string `yaml:"kms_key_id"`
	File     string `yaml:"file"`
}

// SyncConfig declares reusable sync routes (targets) + optional hub endpoint.
type SyncConfig struct {
	Targets []SyncTarget `yaml:"targets"`
	Hub     *HubConfig   `yaml:"hub,omitempty"`
}

// SyncTarget is one declared sync destination.
type SyncTarget struct {
	Type    string `yaml:"type"`              // github | cloudflare | dotenv
	Env     string `yaml:"env,omitempty"`     // source environment (default: default_env)
	Repo    string `yaml:"repo,omitempty"`    // github
	Worker  string `yaml:"worker,omitempty"`  // cloudflare worker script
	Pages   string `yaml:"pages,omitempty"`   // cloudflare pages project
	Account string `yaml:"account,omitempty"` // cloudflare account id
	File    string `yaml:"file,omitempty"`    // dotenv
}

// HubConfig points at the vault dashboard manifest endpoint.
type HubConfig struct {
	URL string `yaml:"url"`
}

// Validate checks all required fields and cross-references.
func (c *Config) Validate() error {
	if c.Version == "" {
		return fmt.Errorf("config: version is required")
	}
	if c.Version != "1" {
		return fmt.Errorf("config: unsupported version %q (expected \"1\")", c.Version)
	}
	if len(c.Environments) == 0 {
		return fmt.Errorf("config: at least one environment is required in environments")
	}
	if c.DefaultEnv != "" {
		if _, ok := c.Environments[c.DefaultEnv]; !ok {
			return fmt.Errorf("config: default_env %q not found in environments", c.DefaultEnv)
		}
	}
	for name, env := range c.Environments {
		if err := env.validate(name); err != nil {
			return err
		}
	}
	if c.Sync != nil {
		for i := range c.Sync.Targets {
			if err := c.Sync.Targets[i].validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *Environment) validate(name string) error {
	if e.Provider == "" {
		return fmt.Errorf("config: environment %q: provider is required", name)
	}
	switch e.Provider {
	case "aws":
		if e.Path == "" {
			return fmt.Errorf("config: environment %q: path is required for aws provider", name)
		}
	case "local":
		if e.File == "" {
			return fmt.Errorf("config: environment %q: file is required for local provider", name)
		}
	default:
		return fmt.Errorf("config: environment %q: unknown provider %q", name, e.Provider)
	}
	return nil
}

func (s *SyncTarget) validate() error {
	switch s.Type {
	case "github":
		if s.Repo == "" {
			return fmt.Errorf("config: github sync target: repo is required")
		}
	case "cloudflare":
		if s.Worker == "" && s.Pages == "" {
			return fmt.Errorf("config: cloudflare sync target: worker or pages is required")
		}
		if s.Worker != "" && s.Pages != "" {
			return fmt.Errorf("config: cloudflare sync target: set exactly one of worker/pages")
		}
	case "dotenv":
		// file optional (defaults to .env at build time)
	default:
		return fmt.Errorf("config: unknown sync target type %q", s.Type)
	}
	return nil
}
