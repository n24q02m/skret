package cli

import (
	"fmt"
	"os"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	skaws "github.com/n24q02m/skret/internal/provider/aws"
	"github.com/n24q02m/skret/internal/provider/local"
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
func loadProvider() (*config.ResolvedConfig, provider.SecretProvider, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil, fmt.Errorf("get working directory: %w", err)
	}

	cfgPath, err := config.Discover(cwd)
	if err != nil {
		return nil, nil, fmt.Errorf("find config: %w", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, err
	}

	opts := config.ResolveOpts{
		Env:      globalOpts.env,
		Provider: globalOpts.provider,
		Path:     globalOpts.path,
		Region:   globalOpts.region,
		Profile:  globalOpts.profile,
		File:     globalOpts.file,
	}
	resolved, err := config.Resolve(cfg, opts)
	if err != nil {
		return nil, nil, err
	}

	reg := defaultRegistry()
	p, err := reg.New(resolved.Provider, resolved)
	if err != nil {
		return nil, nil, err
	}

	return resolved, p, nil
}

// secretKeyToEnvVar strips the path prefix and converts to uppercase env var name.
func secretKeyToEnvVar(key, pathPrefix string) string {
	name := key
	if len(pathPrefix) > 0 && len(key) > len(pathPrefix) {
		trimmed := key[len(pathPrefix):]
		if len(trimmed) > 0 && trimmed[0] == '/' {
			trimmed = trimmed[1:]
		}
		if len(trimmed) > 0 {
			name = trimmed
		}
	}
	result := make([]byte, 0, len(name))
	for i := range len(name) {
		c := name[i]
		if c == '/' {
			c = '_'
		}
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		result = append(result, c)
	}
	return string(result)
}
