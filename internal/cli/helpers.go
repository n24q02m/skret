package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/n24q02m/skret/internal/config"
	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	skaws "github.com/n24q02m/skret/internal/provider/aws"
	"github.com/n24q02m/skret/internal/provider/local"
	"github.com/n24q02m/skret/pkg/skret"
)

// configNotFoundMsg is the actionable error shown when a command needs a config
// but neither a .skret.yaml nor --path is available.
const configNotFoundMsg = "no .skret.yaml found here or in any parent up to the git root, and no --path given. Run 'skret init' to create one, or pass --path=/namespace/env (e.g. --path=/myapp/prod)"

// defaultRegistry returns the global provider registry with all built-in providers.
func defaultRegistry() *provider.Registry {
	reg := provider.NewRegistry()
	reg.Register("local", local.New)
	reg.Register("aws", skaws.New)
	return reg
}

// loadProvider resolves config (from .skret.yaml, or synthesized from --path)
// and creates the appropriate provider.
func loadProvider(opts *GlobalOpts) (*config.ResolvedConfig, provider.SecretProvider, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil, skret.NewError(skret.ExitConfigError, "get working directory failed", err)
	}

	resolveOpts := config.ResolveOpts{
		Env:      opts.Env,
		Provider: opts.Provider,
		Path:     opts.Path,
		Region:   opts.Region,
		Profile:  opts.Profile,
		File:     opts.File,
	}

	// Prefer a discovered .skret.yaml so its provider/region/profile are kept;
	// --path then overrides the path within it (config.Resolve precedence).
	// Only synthesize an ephemeral config when no .skret.yaml exists and --path
	// was supplied — that is what makes ad-hoc `skret ... --path=/ns/env` work.
	var cfg *config.Config
	cfgPath, derr := config.Discover(cwd)
	switch {
	case derr == nil:
		loaded, lerr := config.Load(cfgPath)
		if lerr != nil {
			return nil, nil, skret.NewError(skret.ExitConfigError, "load config failed", lerr)
		}
		cfg = loaded
	case opts.Path != "":
		cfg = config.EphemeralConfig(resolveOpts)
	default:
		return nil, nil, skret.NewError(skret.ExitConfigError, configNotFoundMsg, derr)
	}

	resolved, err := config.Resolve(cfg, resolveOpts)
	if err != nil {
		return nil, nil, skret.NewError(skret.ExitConfigError, "resolve config failed", err)
	}

	reg := defaultRegistry()
	p, err := reg.New(resolved.Provider, resolved)
	if err != nil {
		return nil, nil, skret.NewError(skret.ExitProviderError, fmt.Sprintf("init provider %q failed", resolved.Provider), err)
	}

	// Config-resolution debug output (keys/paths only, never secret values).
	slog.Debug("skret: configuration resolved", "provider", resolved.Provider, "path", resolved.Path)

	return resolved, p, nil
}

// KeyToEnvName is the single source of truth for converting secret keys to env var names.
// Delegates to exec.KeyToEnvName to avoid duplication.
var KeyToEnvName = skexec.KeyToEnvName

// resolveKeyArg qualifies a user-supplied key with the resolved path prefix so
// get/set/delete/history/rollback accept the same key strings list/env display.
// Returns the resolved key and whether a shell-mangled prefix was recovered.
func resolveKeyArg(resolvedPath, raw string) (string, bool) {
	return config.ResolveKey(resolvedPath, raw)
}
