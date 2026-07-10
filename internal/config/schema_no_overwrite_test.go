package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_SyncTargetNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.WriteFile(p, []byte(`
version: "1"
default_env: prod
project: t
environments:
  prod:
    provider: aws
    path: /t/prod
sync:
  targets:
    - type: github
      repo: o/r
      no_overwrite: true
    - type: cloudflare
      worker: w
      account: a
`), 0o644))

	cfg, err := Load(p)
	require.NoError(t, err)
	require.Len(t, cfg.Sync.Targets, 2)
	assert.True(t, cfg.Sync.Targets[0].NoOverwrite)
	assert.False(t, cfg.Sync.Targets[1].NoOverwrite)
}

func TestLoad_UnknownSyncTargetFieldStillErrors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.WriteFile(p, []byte(`
version: "1"
default_env: prod
project: t
environments:
  prod:
    provider: aws
    path: /t/prod
sync:
  targets:
    - type: github
      repo: o/r
      no_overwrit: true
`), 0o644))

	_, err := Load(p)
	require.Error(t, err) // strict KnownFields(true) tu #516 van phai bat typo
}
