package config

import (
	"fmt"
	"os"
)

// ResolveOpts holds CLI flag overrides for config resolution.
type ResolveOpts struct {
	Env      string // --env flag or SKRET_ENV
	Provider string // --provider flag
	Path     string // --path flag
	Region   string // --region flag
	Profile  string // --profile flag
	File     string // --file flag
}

// ResolvedConfig is the final resolved configuration after precedence resolution.
type ResolvedConfig struct {
	EnvName  string
	Provider string
	Path     string
	Region   string
	Profile  string
	KMSKeyID string
	File     string
	Required []string
	Exclude  []string
}

// Resolve applies the precedence chain: CLI flags > env vars > config file > defaults.
func Resolve(cfg *Config, opts ResolveOpts) (*ResolvedConfig, error) {
	envName := firstNonEmpty(opts.Env, os.Getenv("SKRET_ENV"), cfg.DefaultEnv)
	if envName == "" && len(cfg.Environments) == 1 {
		for name := range cfg.Environments {
			envName = name
		}
	}
	if envName == "" {
		return nil, fmt.Errorf("resolve: no environment specified (use --env or set default_env)")
	}

	env, ok := cfg.Environments[envName]
	if !ok {
		return nil, fmt.Errorf("resolve: environment %q not found in config", envName)
	}

	return &ResolvedConfig{
		EnvName:  envName,
		Provider: firstNonEmpty(opts.Provider, os.Getenv("SKRET_PROVIDER"), env.Provider),
		Path:     firstNonEmpty(opts.Path, os.Getenv("SKRET_PATH"), env.Path),
		Region:   firstNonEmpty(opts.Region, os.Getenv("SKRET_REGION"), os.Getenv("AWS_REGION"), env.Region),
		Profile:  firstNonEmpty(opts.Profile, os.Getenv("SKRET_PROFILE"), os.Getenv("AWS_PROFILE"), env.Profile),
		KMSKeyID: env.KMSKeyID,
		File:     firstNonEmpty(opts.File, env.File),
		Required: cfg.Required,
		Exclude:  cfg.Exclude,
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
