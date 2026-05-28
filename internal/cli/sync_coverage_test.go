package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

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
