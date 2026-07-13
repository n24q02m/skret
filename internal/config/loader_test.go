package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_FromFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	err := os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: prod
project: testapp
environments:
  prod:
    provider: aws
    path: /testapp/prod
    region: us-east-1
`), 0o644)
	require.NoError(t, err)

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "testapp", cfg.Project)
	assert.Equal(t, "prod", cfg.DefaultEnv)
	assert.Equal(t, "aws", cfg.Environments["prod"].Provider)
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "nonexistent", ".skret.yaml"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	err := os.WriteFile(cfgPath, []byte(`invalid: [yaml: bad`), 0o644)
	require.NoError(t, err)

	_, err = config.Load(cfgPath)
	assert.Error(t, err)
}

func TestLoad_UnknownField(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	err := os.WriteFile(cfgPath, []byte(`
version: "1"
bogus_field: x
environments:
  prod:
    provider: local
    file: ./.secrets.prod.yaml
`), 0o644)
	require.NoError(t, err)

	_, err = config.Load(cfgPath)
	assert.ErrorContains(t, err, "bogus_field")
}

func TestLoad_ValidationError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	err := os.WriteFile(cfgPath, []byte(`version: "1"`), 0o644)
	require.NoError(t, err)

	_, err = config.Load(cfgPath)
	assert.ErrorContains(t, err, "environments")
}

func TestDiscover_FindsInCurrentDir(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	err := os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
`), 0o644)
	require.NoError(t, err)

	found, err := config.Discover(dir)
	require.NoError(t, err)
	assert.Equal(t, cfgPath, found)
}

func TestDiscover_WalksUpToGitRoot(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, ".git"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "apps", "api"), 0o755)
	cfgPath := filepath.Join(root, ".skret.yaml")
	err := os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
`), 0o644)
	require.NoError(t, err)

	found, err := config.Discover(filepath.Join(root, "apps", "api"))
	require.NoError(t, err)
	assert.Equal(t, cfgPath, found)
}

func TestDiscover_NotFound(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	_, err := config.Discover(dir)
	assert.ErrorIs(t, err, config.ErrConfigNotFound)
}

// TestLoad_V1ConfigWithoutSyncStillValid is a backwards-compat regression
// guard for the B1 sync-fabric feature: a pre-existing .skret.yaml with no
// sync: block must still load and validate exactly as before, with Sync left
// nil (no behavior change for callers that never touch the sync fabric).
func TestLoad_V1ConfigWithoutSyncStillValid(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	err := os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: prod
environments:
  prod:
    provider: aws
    path: /a/prod
    region: ap-southeast-1
`), 0o644)
	require.NoError(t, err)

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	assert.Nil(t, cfg.Sync)
}

// TestLoad_SecondBrokenEnvDoesNotBlockLoad is Load()'s half of the C1 root
// cause 2 fix: Load() only runs the structural Validate() now, so a config
// file with a second, incomplete environment (prod: aws, no path) must
// still load successfully -- the per-provider check only fires later, in
// Resolve(), for whichever env is actually selected.
func TestLoad_SecondBrokenEnvDoesNotBlockLoad(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
  prod:
    provider: aws
`), 0o644))

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err, "Load must succeed even though the unselected prod env is missing its required path")
	assert.Equal(t, "aws", cfg.Environments["prod"].Provider)
}

// TestLoad_OldStyleExplicitEmptyFieldsStillDecode is the regression guard
// for adding omitempty (Task 7 T7b): omitempty only changes MARSHAL
// (encode) output, never DECODE -- an old .skret.yaml written before this
// fix, with path/region/profile/kms_key_id explicitly present as "", must
// still Load() successfully under strict yaml.KnownFields(true).
func TestLoad_OldStyleExplicitEmptyFieldsStillDecode(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    path: ""
    region: ""
    profile: ""
    kms_key_id: ""
    file: ./.secrets.dev.yaml
`), 0o644))

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "local", cfg.Environments["dev"].Provider)
}
