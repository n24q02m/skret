package config_test

import (
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolve_DefaultEnv(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Provider: "aws", Path: "/app/prod", Region: "us-east-1"},
		},
	}
	opts := config.ResolveOpts{}
	resolved, err := config.Resolve(cfg, opts)
	require.NoError(t, err)

	assert.Equal(t, "aws", resolved.Provider)
	assert.Equal(t, "/app/prod", resolved.Path)
	assert.Equal(t, "us-east-1", resolved.Region)
	assert.Equal(t, "prod", resolved.EnvName)
}

func TestResolve_ExplicitEnv(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod":    {Provider: "aws", Path: "/app/prod"},
			"staging": {Provider: "aws", Path: "/app/staging"},
		},
	}
	opts := config.ResolveOpts{Env: "staging"}
	resolved, err := config.Resolve(cfg, opts)
	require.NoError(t, err)

	assert.Equal(t, "/app/staging", resolved.Path)
	assert.Equal(t, "staging", resolved.EnvName)
}

func TestResolve_CLIFlagsOverride(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Provider: "aws", Path: "/app/prod", Region: "us-east-1"},
		},
	}
	opts := config.ResolveOpts{
		Provider: "local",
		Path:     "/override/path",
		Region:   "eu-west-1",
		File:     "./local.yaml",
	}
	resolved, err := config.Resolve(cfg, opts)
	require.NoError(t, err)

	assert.Equal(t, "local", resolved.Provider)
	assert.Equal(t, "/override/path", resolved.Path)
	assert.Equal(t, "eu-west-1", resolved.Region)
	assert.Equal(t, "./local.yaml", resolved.File)
}

func TestResolve_EnvVarsOverride(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod":    {Provider: "aws", Path: "/app/prod"},
			"staging": {Provider: "aws", Path: "/app/staging"},
		},
	}
	opts := config.ResolveOpts{Env: "staging"}
	t.Setenv("SKRET_PATH", "/env-override")
	t.Setenv("SKRET_REGION", "ap-northeast-1")

	resolved, err := config.Resolve(cfg, opts)
	require.NoError(t, err)

	assert.Equal(t, "/env-override", resolved.Path)
	assert.Equal(t, "ap-northeast-1", resolved.Region)
}

func TestResolve_EnvNotFound(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Provider: "aws", Path: "/app/prod"},
		},
	}
	opts := config.ResolveOpts{Env: "nonexistent"}
	_, err := config.Resolve(cfg, opts)
	assert.ErrorContains(t, err, "nonexistent")
}

func TestResolve_SingleEnvAutoSelect(t *testing.T) {
	cfg := &config.Config{
		Version: "1",
		Environments: map[string]config.Environment{
			"dev": {Provider: "local", File: "./secrets.yaml"},
		},
	}
	opts := config.ResolveOpts{}
	resolved, err := config.Resolve(cfg, opts)
	require.NoError(t, err)

	assert.Equal(t, "dev", resolved.EnvName)
	assert.Equal(t, "local", resolved.Provider)
}

func TestResolve_NoEnvNoDefault(t *testing.T) {
	cfg := &config.Config{
		Version: "1",
		Environments: map[string]config.Environment{
			"prod":    {Provider: "aws", Path: "/app/prod"},
			"staging": {Provider: "aws", Path: "/app/staging"},
		},
	}
	opts := config.ResolveOpts{}
	_, err := config.Resolve(cfg, opts)
	assert.ErrorContains(t, err, "no environment specified")
}

func TestResolve_CLIFlagsPrecedenceOverEnvVars(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Provider: "aws", Path: "/app/prod", Region: "us-east-1"},
		},
	}
	t.Setenv("SKRET_PATH", "/env-path")
	t.Setenv("SKRET_REGION", "env-region")
	opts := config.ResolveOpts{
		Path:   "/flag-path",
		Region: "flag-region",
	}
	resolved, err := config.Resolve(cfg, opts)
	require.NoError(t, err)

	assert.Equal(t, "/flag-path", resolved.Path)
	assert.Equal(t, "flag-region", resolved.Region)
}

func TestResolve_RequiredAndExclude(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Provider: "aws", Path: "/app/prod"},
		},
		Required: []string{"DB_URL", "API_KEY"},
		Exclude:  []string{"DEBUG_TOKEN"},
	}
	opts := config.ResolveOpts{}
	resolved, err := config.Resolve(cfg, opts)
	require.NoError(t, err)

	assert.Equal(t, []string{"DB_URL", "API_KEY"}, resolved.Required)
	assert.Equal(t, []string{"DEBUG_TOKEN"}, resolved.Exclude)
}

func TestResolve_KMSKeyIDPassthrough(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Provider: "aws", Path: "/app/prod", KMSKeyID: "arn:aws:kms:us-east-1:123:key/abc"},
		},
	}
	opts := config.ResolveOpts{}
	resolved, err := config.Resolve(cfg, opts)
	require.NoError(t, err)

	assert.Equal(t, "arn:aws:kms:us-east-1:123:key/abc", resolved.KMSKeyID)
}

func TestResolve_SKRETEnvOverride(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod":    {Provider: "aws", Path: "/app/prod"},
			"staging": {Provider: "aws", Path: "/app/staging"},
		},
	}
	t.Setenv("SKRET_ENV", "staging")
	opts := config.ResolveOpts{}
	resolved, err := config.Resolve(cfg, opts)
	require.NoError(t, err)

	assert.Equal(t, "staging", resolved.EnvName)
}

// --- Wave 2 T1: per-provider requirement checks moved from Validate() to
// Resolve(), scoped to only the selected env (fix C1 root cause 2 + I8) ---

func TestResolve_EnvironmentMissingProvider(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Path: "/p/prod"},
		},
	}
	_, err := config.Resolve(cfg, config.ResolveOpts{})
	assert.ErrorContains(t, err, "provider")
}

func TestResolve_AWSMissingPath(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Provider: "aws"},
		},
	}
	_, err := config.Resolve(cfg, config.ResolveOpts{})
	assert.ErrorContains(t, err, "path")
}

func TestResolve_LocalMissingFile(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "dev",
		Environments: map[string]config.Environment{
			"dev": {Provider: "local"},
		},
	}
	_, err := config.Resolve(cfg, config.ResolveOpts{})
	assert.ErrorContains(t, err, "file")
}

func TestResolve_UnknownProvider(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Provider: "gcp", Path: "/p/prod"},
		},
	}
	_, err := config.Resolve(cfg, config.ResolveOpts{})
	assert.ErrorContains(t, err, "unknown provider")
}

// TestResolve_ScopedValidation_BrokenEnvDoesNotBlockGoodEnv is the direct
// regression guard for audit I8 / C1 root cause 2: a second, incomplete
// environment must not block Resolve() for a different, already-working
// one, and selecting the broken one directly must still error exactly as
// before ("env hỏng không được chặn env lành; chọn đúng env hỏng thì error
// như cũ" -- spec Wave 2 T1).
func TestResolve_ScopedValidation_BrokenEnvDoesNotBlockGoodEnv(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "dev",
		Environments: map[string]config.Environment{
			"dev":  {Provider: "local", File: "./.secrets.dev.yaml"},
			"prod": {Provider: "aws"}, // deliberately incomplete: no Path
		},
	}

	good, err := config.Resolve(cfg, config.ResolveOpts{Env: "dev"})
	require.NoError(t, err)
	assert.Equal(t, "local", good.Provider)

	_, err = config.Resolve(cfg, config.ResolveOpts{Env: "prod"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "path is required for aws provider")
}

func TestResolve_EnvNotFound_ListsAvailable(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod":    {Provider: "aws", Path: "/app/prod"},
			"staging": {Provider: "aws", Path: "/app/staging"},
		},
	}
	_, err := config.Resolve(cfg, config.ResolveOpts{Env: "nonexistent"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "nonexistent")
	assert.ErrorContains(t, err, "prod")
	assert.ErrorContains(t, err, "staging")
}

// --- Wave 2 T2: --path shell-mangling guard propagates through Resolve()
// (fix C2) ---

func TestResolve_PathMangled_RecoversAndFlags(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Provider: "aws", Path: "/fallback/prod"},
		},
	}
	opts := config.ResolveOpts{Path: "C:/Users/x/scoop/apps/git/2.54.0/myapp/dev"}
	resolved, err := config.Resolve(cfg, opts)
	require.NoError(t, err)
	assert.Equal(t, "/myapp/dev", resolved.Path)
	assert.True(t, resolved.PathMangled)
}

func TestResolve_PathNotMangled_FlagFalse(t *testing.T) {
	cfg := &config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Provider: "aws", Path: "/fallback/prod"},
		},
	}
	resolved, err := config.Resolve(cfg, config.ResolveOpts{})
	require.NoError(t, err)
	assert.Equal(t, "/fallback/prod", resolved.Path)
	assert.False(t, resolved.PathMangled)
}
