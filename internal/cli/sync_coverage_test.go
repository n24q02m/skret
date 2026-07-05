package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/syncer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncOptions_Run_LoadProviderError(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	o := &syncOptions{global: &GlobalOpts{}}
	err := o.run(nil)
	assert.Error(t, err)
}

func TestSyncOptions_Run_BuildSyncersError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets: {}"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	o := &syncOptions{
		global: &GlobalOpts{},
		to:     "invalid",
	}
	cmd := NewRootCmd()
	err := o.run(cmd)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown target")
}

func TestSyncOptions_Run_SyncError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V"), 0o600))

	// Create a directory where the dotenv file should be. This should cause s.Sync to fail.
	require.NoError(t, os.Mkdir(filepath.Join(dir, "blocked_dir"), 0o755))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	o := &syncOptions{
		global: &GlobalOpts{},
		to:     "dotenv",
		file:   "blocked_dir",
	}
	cmd := NewRootCmd()
	err := o.run(cmd)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sync failed")
}

func TestSyncOptions_Run_LoadStateError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V"), 0o600))

	// Setup HOME to point to a temp dir
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}

	// Create an invalid state file
	stateDir := filepath.Join(home, ".skret", "sync-state")
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	stateFile := filepath.Join(stateDir, "dotenv-.env.json")
	require.NoError(t, os.WriteFile(stateFile, []byte("invalid json"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	o := &syncOptions{
		global:        &GlobalOpts{},
		to:            "dotenv",
		file:          ".env",
		skipUnchanged: true,
	}
	cmd := NewRootCmd()
	err := o.run(cmd)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "load state failed")
}

func TestSyncOptions_Run_SaveStateError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V"), 0o600))

	// Setup HOME to point to a temp dir
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}

	// Make the state path blocked by a directory instead of a file
	stateDir := filepath.Join(home, ".skret", "sync-state")
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	require.NoError(t, os.Mkdir(filepath.Join(stateDir, "dotenv-.env.json.tmp"), 0o755))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	o := &syncOptions{
		global:        &GlobalOpts{},
		to:            "dotenv",
		file:          ".env",
		skipUnchanged: true,
	}

	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := o.run(cmd)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "save state failed")
}

func TestSyncOptions_Run_SkipUnchanged_Output(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V"), 0o600))

	// Setup HOME to point to a temp dir
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	o := &syncOptions{
		global:        &GlobalOpts{},
		to:            "dotenv",
		file:          ".env",
		skipUnchanged: true,
	}

	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	// First run to save state
	require.NoError(t, o.run(cmd))
	buf.Reset()

	// Second run: should skip unchanged
	require.NoError(t, o.run(cmd))
	assert.Contains(t, buf.String(), "Skipped 1 unchanged")
}

// --- Task 5: comma-list --to + .skret.yaml sync.targets wiring ---

// TestNewSyncCmd_ToFlagDefaultsToEmpty is the root-cause regression guard for
// the review finding: a "dotenv" flag default meant a bare `skret sync`
// NEVER had an empty o.to, so resolveTargets' `if o.to != ""` filter always
// dropped every declared sync.targets entry whose type wasn't dotenv. This
// test goes through REAL cobra flag registration/parsing (not a zero-value
// &syncOptions{} struct), which is what the earlier tests missed.
func TestNewSyncCmd_ToFlagDefaultsToEmpty(t *testing.T) {
	cmd := newSyncCmd(&GlobalOpts{})

	assert.Equal(t, "", cmd.Flags().Lookup("to").DefValue,
		"--to default must be empty so config sync.targets are honored on a bare `skret sync`")

	require.NoError(t, cmd.ParseFlags([]string{}))
	got, err := cmd.Flags().GetString("to")
	require.NoError(t, err)
	assert.Equal(t, "", got, "parsed --to value must be empty with no flag passed")
}

func TestSyncOptions_ResolveTargets_NoFlagsNoConfig_DefaultsDotenv(t *testing.T) {
	o := &syncOptions{}
	targets, err := o.resolveTargets(nil)
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, "dotenv", targets[0].Type)
}

func TestSyncOptions_ResolveTargets_CommaListFlags(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	o := &syncOptions{to: "dotenv,github", file: "x.env", githubRepo: "owner/repo"}
	targets, err := o.resolveTargets(nil)
	require.NoError(t, err)
	require.Len(t, targets, 2)
	assert.Equal(t, "dotenv", targets[0].Type)
	assert.Equal(t, "x.env", targets[0].Fields["file"])
	assert.Equal(t, "github", targets[1].Type)
	assert.Equal(t, "owner/repo", targets[1].Fields["repo"])
	assert.Equal(t, "ghp_test", targets[1].Token)
}

func TestSyncOptions_ResolveTargets_ConfigDeclaredTargets(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	sc := &config.SyncConfig{Targets: []config.SyncTarget{
		{Type: "dotenv", File: "from-config.env"},
		{Type: "github", Repo: "o/r"},
	}}
	o := &syncOptions{}
	targets, err := o.resolveTargets(sc)
	require.NoError(t, err)
	require.Len(t, targets, 2)
	assert.Equal(t, "dotenv", targets[0].Type)
	assert.Equal(t, "from-config.env", targets[0].Fields["file"])
	assert.Equal(t, "github", targets[1].Type)
	assert.Equal(t, "o/r", targets[1].Fields["repo"])
	assert.Equal(t, "ghp_test", targets[1].Token)
}

func TestSyncOptions_ResolveTargets_ToFiltersConfigDeclaredTargets(t *testing.T) {
	sc := &config.SyncConfig{Targets: []config.SyncTarget{
		{Type: "dotenv", File: "a.env"},
		{Type: "github", Repo: "o/r"},
	}}
	o := &syncOptions{to: "dotenv"}
	targets, err := o.resolveTargets(sc)
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, "dotenv", targets[0].Type)
}

func TestSyncOptions_ResolveTargets_FlagsOverrideConfig(t *testing.T) {
	// --to set but no target of that type is declared in config: falls back to flags.
	sc := &config.SyncConfig{Targets: []config.SyncTarget{
		{Type: "github", Repo: "o/r"},
	}}
	o := &syncOptions{to: "dotenv", file: "flag.env"}
	targets, err := o.resolveTargets(sc)
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, "dotenv", targets[0].Type)
	assert.Equal(t, "flag.env", targets[0].Fields["file"])
}

// TestSyncOptions_ResolveTargets_MixedToPerTypeFallback is the regression
// guard for the Task 8 review finding: the old fallback was all-or-nothing
// (it only ran when NO requested --to type matched sync.targets), so
// --to=github,dotenv with only a github target declared would silently drop
// dotenv (github matched config -> out non-empty -> flags fallback never
// ran). Each requested type must now be resolved independently: github
// comes from the declared sync.targets entry, dotenv (undeclared) must
// still be built from flags instead of vanishing.
func TestSyncOptions_ResolveTargets_MixedToPerTypeFallback(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	sc := &config.SyncConfig{Targets: []config.SyncTarget{
		{Type: "github", Repo: "o/r"},
	}}
	o := &syncOptions{to: "github,dotenv", githubRepo: "o/r", file: "out.env"}
	targets, err := o.resolveTargets(sc)
	require.NoError(t, err)
	require.Len(t, targets, 2)

	// --to order preserved: github (from config) first, then dotenv (from flags).
	assert.Equal(t, "github", targets[0].Type)
	assert.Equal(t, "o/r", targets[0].Fields["repo"])
	assert.Equal(t, "ghp_test", targets[0].Token)

	assert.Equal(t, "dotenv", targets[1].Type)
	assert.Equal(t, "out.env", targets[1].Fields["file"])
}

func TestSyncOptions_TargetFromFlags_CloudflareRequiresConfig(t *testing.T) {
	o := &syncOptions{}
	_, err := o.targetFromFlags("cloudflare")
	require.ErrorContains(t, err, "sync.targets entry")
}

func TestTargetFromConfig_CloudflareExpandsAccountEnv(t *testing.T) {
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "acct-123")
	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	tc := targetFromConfig(config.SyncTarget{Type: "cloudflare", Worker: "w", Account: "${CLOUDFLARE_ACCOUNT_ID}"})
	assert.Equal(t, "cloudflare", tc.Type)
	assert.Equal(t, "w", tc.Fields["worker"])
	assert.Equal(t, "acct-123", tc.Fields["account"])
	assert.Equal(t, "cf-tok", tc.Token)
}

func TestTokenForType(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_x")
	t.Setenv("CLOUDFLARE_API_TOKEN", "cf_x")
	assert.Equal(t, "ghp_x", tokenForType("github"))
	assert.Equal(t, "cf_x", tokenForType("cloudflare"))
	assert.Equal(t, "", tokenForType("dotenv"))
}

func TestTargetStateID_Cloudflare(t *testing.T) {
	worker := syncer.NewCloudflare("acc", "worker-name", "", "tok", "")
	assert.Equal(t, "worker/worker-name",
		targetStateID(worker, syncer.TargetConfig{Fields: map[string]string{"worker": "worker-name"}}))

	pages := syncer.NewCloudflare("acc", "", "pages-name", "tok", "")
	assert.Equal(t, "pages/pages-name",
		targetStateID(pages, syncer.TargetConfig{Fields: map[string]string{"pages": "pages-name"}}))
}

func TestTargetStateID_GithubAndDotenvDefault(t *testing.T) {
	gh := syncer.NewGitHub("o", "r", "tok", "")
	assert.Equal(t, "o/r", targetStateID(gh, syncer.TargetConfig{Fields: map[string]string{"repo": "o/r"}}))

	dv := syncer.NewDotenv(".env")
	assert.Equal(t, ".env", targetStateID(dv, syncer.TargetConfig{Fields: map[string]string{}}))
}

func TestLoadSyncConfig_NoConfigFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	sc, err := loadSyncConfig()
	require.NoError(t, err)
	assert.Nil(t, sc)
}

func TestLoadSyncConfig_WithSyncBlock(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
sync:
  targets:
    - type: dotenv
      file: configured.env
`), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	sc, err := loadSyncConfig()
	require.NoError(t, err)
	require.NotNil(t, sc)
	require.Len(t, sc.Targets, 1)
	assert.Equal(t, "configured.env", sc.Targets[0].File)
}

func TestSyncOptions_Run_ConfigDeclaredDotenvTarget(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
sync:
  targets:
    - type: dotenv
      file: from-config.env
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	// o.to left empty: declared config targets should be used (no --to override).
	o := &syncOptions{global: &GlobalOpts{}}
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	require.NoError(t, o.run(cmd))

	data, err := os.ReadFile(filepath.Join(dir, "from-config.env"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "K=")
}

func TestSyncOptions_Run_ToFiltersConfigTargets(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
sync:
  targets:
    - type: dotenv
      file: filtered.env
    - type: github
      repo: should/not-run
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	// --to=dotenv must filter out the declared github target; if it leaked
	// through, this test would fail/hang trying to reach the GitHub API.
	o := &syncOptions{global: &GlobalOpts{}, to: "dotenv"}
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	require.NoError(t, o.run(cmd))

	_, err := os.Stat(filepath.Join(dir, "filtered.env"))
	assert.NoError(t, err)
}

func TestSyncOptions_Run_ConfigDeclaredTarget_BuildError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
sync:
  targets:
    - type: cloudflare
      worker: w
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	// No account declared in .skret.yaml -> the cloudflare factory rejects
	// it at syncer.Build time; run() must surface that as "build targets".
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	o := &syncOptions{global: &GlobalOpts{}}
	cmd := NewRootCmd()
	err := o.run(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build targets")
}

func TestSyncOptions_Run_RespectsTopLevelExclude(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
exclude:
  - EXCLUDED_KEY
sync:
  targets:
    - type: dotenv
      file: out.env
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte("version: \"1\"\nsecrets:\n  K: V\n  EXCLUDED_KEY: skip_me"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	o := &syncOptions{global: &GlobalOpts{}}
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	require.NoError(t, o.run(cmd))

	data, err := os.ReadFile(filepath.Join(dir, "out.env"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "K=V")
	assert.NotContains(t, string(data), "EXCLUDED_KEY")
	assert.NotContains(t, string(data), "skip_me")
}

func TestFilterExcluded(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "DB_URL", Value: "postgres://localhost"},
		{Key: "api-key", Value: "secret"},
		{Key: "DEBUG_TOKEN", Value: "tok"},
	}

	out := filterExcluded(secrets, "", []string{"debug_token"})

	require.Len(t, out, 2)
	assert.Equal(t, "DB_URL", out[0].Key)
	assert.Equal(t, "api-key", out[1].Key)
}

func TestFilterExcluded_NoExclude_ReturnsSameSlice(t *testing.T) {
	secrets := []*provider.Secret{{Key: "K", Value: "V"}}
	out := filterExcluded(secrets, "", nil)
	assert.Equal(t, secrets, out)
}

func TestLoadSyncConfig_LoadError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	// Malformed .skret.yaml: fails config.Load.
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte("version: \"1\"\nenvironments: [not-a-map]"), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	sc, err := loadSyncConfig()
	require.Error(t, err)
	assert.Nil(t, sc)
}
