package cli

import (
	"fmt"
	"os"

	"github.com/n24q02m/skret/internal/config"
	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	skaws "github.com/n24q02m/skret/internal/provider/aws"
	"github.com/n24q02m/skret/internal/provider/local"
	"github.com/n24q02m/skret/pkg/skret"
)

// defaultRegistry returns the global provider registry with all built-in providers.
func defaultRegistry() *provider.Registry {
	reg := provider.NewRegistry()
	reg.Register("local", func(cfg *config.ResolvedConfig) (provider.SecretProvider, error) {
		return local.New(cfg)
	})
	reg.Register("aws", func(cfg *config.ResolvedConfig) (provider.SecretProvider, error) {
		return skaws.New(cfg)
	})
	return reg
}

// loadProvider discovers config, resolves it, and creates the appropriate provider.
func loadProvider(opts *GlobalOpts) (*config.ResolvedConfig, provider.SecretProvider, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil, skret.NewError(skret.ExitConfigError, "get working directory failed", err)
	}

	cfgPath, err := config.Discover(cwd)
	if err != nil {
		return nil, nil, skret.NewError(skret.ExitConfigError, "find config failed", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, skret.NewError(skret.ExitConfigError, "load config failed", err)
	}

	resolveOpts := config.ResolveOpts{
		Env:      opts.Env,
		Provider: opts.Provider,
		Path:     opts.Path,
		Region:   opts.Region,
		Profile:  opts.Profile,
		File:     opts.File,
	}
	resolved, err := config.Resolve(cfg, &resolveOpts)
	if err != nil {
		return nil, nil, skret.NewError(skret.ExitConfigError, "resolve config failed", err)
	}

	reg := defaultRegistry()
	p, err := reg.New(resolved.Provider, resolved)
	if err != nil {
		return nil, nil, skret.NewError(skret.ExitProviderError, fmt.Sprintf("init provider %q failed", resolved.Provider), err)
	}

	return resolved, p, nil
}

// KeyToEnvName is the single source of truth for converting secret keys to env var names.
// Delegates to exec.KeyToEnvName to avoid duplication.
var KeyToEnvName = skexec.KeyToEnvName
