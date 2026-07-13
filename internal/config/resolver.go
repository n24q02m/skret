package config

import (
	"fmt"
	"os"
	"sort"
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
	EnvName     string
	Provider    string
	Path        string
	PathMangled bool // true when ResolvePath recovered (or flagged) a shell-mangled --path (audit C2)
	Region      string
	Profile     string
	KMSKeyID    string
	File        string
	Required    []string
	Exclude     []string
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
		return nil, fmt.Errorf("resolve: environment %q not found in config (available: %v)", envName, envNames(cfg.Environments))
	}
	// Per-provider requirement check, scoped to ONLY the selected env (see
	// schema.go's Validate() doc comment -- this used to run for every
	// declared env at Load() time, which meant one incomplete env blocked
	// every command touching a different, working one).
	if err := env.validate(envName); err != nil {
		return nil, err
	}

	flagPath, pathMangled := ResolvePath(opts.Path)

	return &ResolvedConfig{
		EnvName:     envName,
		Provider:    firstNonEmpty(opts.Provider, os.Getenv("SKRET_PROVIDER"), env.Provider),
		Path:        NormalizeSSMPath(firstNonEmpty(flagPath, os.Getenv("SKRET_PATH"), env.Path)),
		PathMangled: pathMangled,
		Region:      firstNonEmpty(opts.Region, os.Getenv("SKRET_REGION"), os.Getenv("AWS_REGION"), env.Region),
		Profile:     firstNonEmpty(opts.Profile, os.Getenv("SKRET_PROFILE"), os.Getenv("AWS_PROFILE"), env.Profile),
		KMSKeyID:    env.KMSKeyID,
		File:        firstNonEmpty(opts.File, env.File),
		Required:    cfg.Required,
		Exclude:     cfg.Exclude,
	}, nil
}

// envNames returns the sorted environment names declared in a config, for
// actionable "environment not found" error messages (audit I6).
func envNames(environments map[string]Environment) []string {
	names := make([]string, 0, len(environments))
	for name := range environments {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
