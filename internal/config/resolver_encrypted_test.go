package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveEncryptedFlag verifies the `encrypted` field flows from the
// environment section of .skret.yaml into ResolvedConfig untouched.
func TestResolveEncryptedFlag(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		wantDefault bool
		wantDev     bool
	}{
		{
			name: "flag on one env only",
			yaml: `version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
    encrypted: true
  prod:
    provider: local
    file: ./.secrets.prod.yaml
`,
			wantDefault: true,
			wantDev:     false,
		},
		{
			name: "flag absent everywhere",
			yaml: `version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
  prod:
    provider: local
    file: ./.secrets.prod.yaml
`,
			wantDefault: false,
			wantDev:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".skret.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tt.yaml), 0o600))

			cfg, err := Load(path)
			require.NoError(t, err)

			dev, err := Resolve(cfg, ResolveOpts{Env: "dev"})
			require.NoError(t, err)
			assert.Equal(t, tt.wantDefault, dev.Encrypted, "dev env")

			prod, err := Resolve(cfg, ResolveOpts{Env: "prod"})
			require.NoError(t, err)
			assert.Equal(t, tt.wantDev, prod.Encrypted, "prod env")
		})
	}
}
