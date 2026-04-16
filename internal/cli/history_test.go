package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderHistory(t *testing.T) {
	tests := []struct {
		name     string
		history  []*provider.Secret
		key      string
		verbose  bool
		expected []string
	}{
		{
			name:    "empty history",
			history: nil,
			key:     "MY_KEY",
			expected: []string{
				"No history found for \"MY_KEY\"",
			},
		},
		{
			name: "non-empty history masked",
			history: []*provider.Secret{
				{
					Key:     "MY_KEY",
					Value:   "secret-value",
					Version: 1,
					Meta: provider.SecretMeta{
						UpdatedAt: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
						CreatedBy: "alice",
					},
				},
			},
			key:     "MY_KEY",
			verbose: false,
			expected: []string{
				"VERSION", "VALUE", "UPDATED AT", "AUTHOR",
				"1", "secr...alue", "2023-01-01T12:00:00Z", "alice",
			},
		},
		{
			name: "non-empty history verbose",
			history: []*provider.Secret{
				{
					Key:     "MY_KEY",
					Value:   "secret-value",
					Version: 1,
					Meta: provider.SecretMeta{
						UpdatedAt: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
						CreatedBy: "alice",
					},
				},
			},
			key:     "MY_KEY",
			verbose: true,
			expected: []string{
				"VERSION", "VALUE", "UPDATED AT", "AUTHOR",
				"1", "secret-value", "2023-01-01T12:00:00Z", "alice",
			},
		},
		{
			name: "short value masking",
			history: []*provider.Secret{
				{
					Key:     "SHORT",
					Value:   "short",
					Version: 1,
					Meta:    provider.SecretMeta{},
				},
			},
			key:     "SHORT",
			verbose: false,
			expected: []string{
				"***",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&buf)

			err := renderHistory(cmd, tt.history, tt.key, tt.verbose)
			assert.NoError(t, err)

			out := buf.String()
			for _, exp := range tt.expected {
				assert.Contains(t, out, exp)
			}
		})
	}
}

func TestHistoryCmd_ExperimentalGuard(t *testing.T) {
	t.Setenv("SKRET_EXPERIMENTAL", "0")
	cmd := newHistoryCmd(&GlobalOpts{})
	cmd.SetArgs([]string{"MY_KEY"})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "experimental")
}

func TestHistoryCmd_Args(t *testing.T) {
	t.Setenv("SKRET_EXPERIMENTAL", "1")
	cmd := newHistoryCmd(&GlobalOpts{})

	// No args
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	assert.Error(t, err)

	// Too many args
	cmd.SetArgs([]string{"K1", "K2"})
	err = cmd.Execute()
	assert.Error(t, err)
}

func TestHistoryCmd_ProviderNotSupported(t *testing.T) {
	t.Setenv("SKRET_EXPERIMENTAL", "1")
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)

	os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
`), 0o644)

	os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte(`
version: "1"
secrets:
  MY_KEY: "my-value"
`), 0o600)

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var buf bytes.Buffer
	cmd := newHistoryCmd(&GlobalOpts{})
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"MY_KEY"})

	err := cmd.Execute()
	// Local provider doesn't support history, so it should return an error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not support this operation")
}
