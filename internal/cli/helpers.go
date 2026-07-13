package cli

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/n24q02m/skret/internal/config"
	skexec "github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
	skaws "github.com/n24q02m/skret/internal/provider/aws"
	"github.com/n24q02m/skret/internal/provider/local"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

// configNotFoundMsg is the actionable error shown when a command needs a config
// but neither a .skret.yaml nor --path is available.
const configNotFoundMsg = "no .skret.yaml found here or in any parent up to the git root, and no --path given. Run 'skret setup' (recommended) or 'skret init' to create one, or pass --path=/namespace/env (e.g. --path=/myapp/prod)"

var providerDisplayNames = map[string]string{
	"aws":   "AWS SSM Parameter Store",
	"local": "a local file provider",
}

// formattedProviderList returns a human-readable list of registered providers
// for use in the root command's tagline.
func formattedProviderList() string {
	reg := defaultRegistry()
	return formatProviderList(reg.Providers())
}

// formatProviderList turns a slice of provider IDs into a human-readable list.
func formatProviderList(names []string) string {
	if len(names) == 0 {
		return ""
	}

	displayNames := make([]string, 0, len(names))
	for _, name := range names {
		if dn, ok := providerDisplayNames[name]; ok {
			displayNames = append(displayNames, dn)
		} else {
			displayNames = append(displayNames, name)
		}
	}

	if len(displayNames) == 1 {
		return displayNames[0]
	}

	last := displayNames[len(displayNames)-1]
	prefix := displayNames[:len(displayNames)-1]
	return strings.Join(prefix, ", ") + " and " + last
}

// defaultRegistry returns the global provider registry with all built-in providers.
func defaultRegistry() *provider.Registry {
	reg := provider.NewRegistry()
	reg.Register("local", local.New)
	reg.Register("aws", skaws.New)
	return reg
}

// resolveConfigFile returns the config path to load: the explicit --config
// path when set (erroring if it does not exist -- never silently falling
// back to discovery), otherwise the discovered .skret.yaml from cwd upward.
func resolveConfigFile(opts *GlobalOpts) (string, error) {
	if opts.Config != "" {
		if _, err := os.Stat(opts.Config); err != nil {
			return "", fmt.Errorf("config file %q: %w", opts.Config, err)
		}
		return opts.Config, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return config.Discover(cwd)
}

// loadProvider resolves config (from .skret.yaml, or synthesized from --path)
// and creates the appropriate provider.
func loadProvider(opts *GlobalOpts) (*config.ResolvedConfig, provider.SecretProvider, error) {
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
	cfgPath, derr := resolveConfigFile(opts)
	switch {
	case derr == nil:
		loaded, lerr := config.Load(cfgPath)
		if lerr != nil {
			return nil, nil, skret.NewError(skret.ExitConfigError, "load config failed", lerr)
		}
		cfg = loaded
	case opts.Config != "":
		// Explicit --config that failed to stat: never fall back.
		return nil, nil, skret.NewError(skret.ExitConfigError, "load config failed", derr)
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

// pathMangledWarningFmt matches resolveKeyArg's key-mangling warning style
// (see get.go/delete.go/rollback.go/set.go/history.go) so the operator sees
// a consistent class of hint regardless of whether the KEY positional arg
// or the --path flag was what Git Bash/MSYS rewrote.
const pathMangledWarningFmt = "warning: --path looked shell-mangled; using %q (set MSYS_NO_PATHCONV=1, or run from PowerShell)\n"

// warnIfPathMangled prints the --path shell-mangling warning to cmd's
// stderr when config.Resolve recovered (or flagged) a --path value
// MSYS/Git-Bash rewrote into an absolute Windows path (fix for audit
// finding C2). Callers invoke this right after loadProvider succeeds.
func warnIfPathMangled(cmd *cobra.Command, resolved *config.ResolvedConfig) {
	if resolved != nil && resolved.PathMangled {
		cmd.PrintErrf(pathMangledWarningFmt, resolved.Path)
	}
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
