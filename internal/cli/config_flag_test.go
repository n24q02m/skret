package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	skret "github.com/n24q02m/skret/pkg/skret"
)

// writeConfigAt writes a minimal local-provider .skret.yaml + secrets file
// into dir and returns the config path.
func writeConfigAt(t *testing.T, dir string) string {
	t.Helper()
	secretsPath := filepath.Join(dir, ".secrets.dev.yaml")
	require.NoError(t, os.WriteFile(secretsPath, []byte(`
version: "1"
secrets:
  ALPHA: "one"
`), 0o600))
	cfgPath := filepath.Join(dir, "custom.skret.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: dev
project: cfgflag-test
environments:
  dev:
    provider: local
    file: `+secretsPath+`
`), 0o644))
	return cfgPath
}

func TestResolveConfigFile_ExplicitAbsolutePath(t *testing.T) {
	cfgPath := writeConfigAt(t, t.TempDir())
	got, err := resolveConfigFile(&GlobalOpts{Config: cfgPath})
	require.NoError(t, err)
	assert.Equal(t, cfgPath, got)
}

func TestResolveConfigFile_ExplicitRelativePath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeConfigAt(t, dir)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	got, err := resolveConfigFile(&GlobalOpts{Config: filepath.Base(cfgPath)})
	require.NoError(t, err)
	assert.Equal(t, filepath.Base(cfgPath), got)
}

func TestResolveConfigFile_ExplicitMissingFails(t *testing.T) {
	_, err := resolveConfigFile(&GlobalOpts{Config: filepath.Join(t.TempDir(), "nope.yaml")})
	require.Error(t, err)
	// KHÔNG rơi về discover: lỗi phải nhắc path được chỉ định.
	assert.Contains(t, err.Error(), "nope.yaml")
}

func TestResolveConfigFile_UnsetFallsBackToDiscover(t *testing.T) {
	dir := t.TempDir()
	// .skret.yaml (tên chuẩn) để Discover tìm thấy.
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`
version: "1"
default_env: dev
project: discover-test
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
`), 0o644))
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	got, err := resolveConfigFile(&GlobalOpts{})
	require.NoError(t, err)
	assert.Contains(t, got, ".skret.yaml")
}

func TestLoadProvider_WithConfigFlag_FromOtherCwd(t *testing.T) {
	cfgPath := writeConfigAt(t, t.TempDir())
	// cwd = một temp dir KHÔNG có .skret.yaml.
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(t.TempDir()))
	defer os.Chdir(origDir)

	resolved, p, err := loadProvider(&GlobalOpts{Config: cfgPath})
	require.NoError(t, err)
	defer p.Close()
	assert.Equal(t, "local", resolved.Provider)
	assert.Equal(t, "dev", resolved.EnvName)
}

func TestLoadProvider_WithConfigFlag_MissingFileIsConfigError(t *testing.T) {
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(t.TempDir()))
	defer os.Chdir(origDir)

	_, _, err := loadProvider(&GlobalOpts{Config: "missing.skret.yaml"})
	require.Error(t, err)
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
}

func TestLoadSyncConfig_WithConfigFlag(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sync.skret.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: dev
project: syncflag-test
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
sync:
  targets:
    - type: dotenv
      file: out.env
`), 0o644))
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(t.TempDir())) // cwd khác, không có .skret.yaml
	defer os.Chdir(origDir)

	sc, err := loadSyncConfig(&GlobalOpts{Config: cfgPath})
	require.NoError(t, err)
	require.NotNil(t, sc)
	require.Len(t, sc.Targets, 1)
	assert.Equal(t, "dotenv", sc.Targets[0].Type)
}

func TestRootCmd_HasConfigFlag(t *testing.T) {
	cmd := NewRootCmd()
	f := cmd.PersistentFlags().Lookup("config")
	require.NotNil(t, f)
}
