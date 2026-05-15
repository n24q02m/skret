package config

import (
	"os"
	"strings"
)

// NormalizeSSMPath ensures a path prefix has the leading slash SSM requires.
// Operators on Git Bash should pass --path without a leading slash
// (e.g. --path=myapp/prod) so MSYS does not rewrite it into a Windows path;
// this restores the canonical "/myapp/prod" form. A drive-lettered value
// (C:\...) is left untouched so a genuinely shell-mangled path fails visibly
// instead of silently querying the wrong prefix.
func NormalizeSSMPath(p string) string {
	if p == "" || strings.HasPrefix(p, "/") {
		return p
	}
	if len(p) >= 2 && p[1] == ':' {
		return p
	}
	return "/" + p
}

// EphemeralConfig builds an in-memory single-environment config from CLI flags
// so commands can run without a .skret.yaml when --path is supplied. Region and
// profile are left to the provider SDK's own resolution chain unless explicitly
// given (skret is a public tool — no hardcoded regional default).
func EphemeralConfig(opts ResolveOpts) *Config {
	env := firstNonEmpty(opts.Env, os.Getenv("SKRET_ENV"), "prod")
	prov := firstNonEmpty(opts.Provider, os.Getenv("SKRET_PROVIDER"), "aws")
	return &Config{
		Version:    "1",
		DefaultEnv: env,
		Environments: map[string]Environment{
			env: {
				Provider: prov,
				Path:     opts.Path, // NormalizeSSMPath applied centrally in Resolve
				Region:   firstNonEmpty(opts.Region, os.Getenv("SKRET_REGION"), os.Getenv("AWS_REGION")),
				Profile:  firstNonEmpty(opts.Profile, os.Getenv("SKRET_PROFILE"), os.Getenv("AWS_PROFILE")),
				File:     opts.File,
			},
		},
	}
}
