package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadSourcesConfig(t *testing.T, targets string) (*Config, error) {
	t.Helper()
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
`+targets), 0o644))
	return Load(p)
}

func TestLoad_SyncTargetSources(t *testing.T) {
	cfg, err := loadSourcesConfig(t, `    - type: github
      repo: o/r
      sources:
        - {}
        - path: /shared/prod
          keys: [TAP_GITHUB_TOKEN]
        - path: /other/prod
          exclude: [RUNTIME_ONLY]
`)
	require.NoError(t, err)
	src := cfg.Sync.Targets[0].Sources
	require.Len(t, src, 3)
	assert.Equal(t, SyncSource{}, src[0])
	assert.Equal(t, SyncSource{Path: "/shared/prod", Keys: []string{"TAP_GITHUB_TOKEN"}}, src[1])
	assert.Equal(t, SyncSource{Path: "/other/prod", Exclude: []string{"RUNTIME_ONLY"}}, src[2])
}

func TestLoad_SyncTargetWithoutSourcesUnchanged(t *testing.T) {
	cfg, err := loadSourcesConfig(t, `    - type: github
      repo: o/r
`)
	require.NoError(t, err)
	assert.Nil(t, cfg.Sync.Targets[0].Sources)
}

func TestLoad_SyncTargetSourcesInvalid(t *testing.T) {
	cases := map[string]struct {
		targets string
		want    string
	}{
		"empty list": {`    - type: github
      repo: o/r
      sources: []
`, "sources is empty"},
		"keys and exclude": {`    - type: github
      repo: o/r
      sources:
        - path: /a
          keys: [A]
          exclude: [B]
`, "both keys and exclude"},
		"blank key": {`    - type: github
      repo: o/r
      sources:
        - path: /a
          keys: [A, " "]
`, "empty key"},
		"blank exclude": {`    - type: github
      repo: o/r
      sources:
        - path: /a
          exclude: [""]
`, "empty exclude"},
		"duplicate path": {`    - type: github
      repo: o/r
      sources:
        - path: /a
        - path: /a/
`, "duplicate source path"},
		"duplicate env path": {`    - type: github
      repo: o/r
      sources:
        - keys: [A]
        - exclude: [B]
`, "duplicate source path"},
		"unknown field": {`    - type: github
      repo: o/r
      sources:
        - pth: /a
`, "pth"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadSourcesConfig(t, tc.targets)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}
