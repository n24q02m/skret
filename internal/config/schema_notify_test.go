package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNotifyConfig_ScalarAndListWebhookURL covers both webhook_url shapes:
// the one-line scalar (the common single-receiver case) and a YAML list
// (fan-out). Both must decode into the same []string.
func TestNotifyConfig_ScalarAndListWebhookURL(t *testing.T) {
	raw := `
version: "1"
environments:
  dev:
    provider: local
    file: secrets.yaml
notify:
  webhook_url: https://hooks.example.com/skret
  secret: top-signing-key
  events:
    - set
    - delete
`
	cfg, err := config.Load(writeTempConfig(t, raw))
	require.NoError(t, err)
	require.NotNil(t, cfg.Notify)
	assert.Equal(t, config.WebhookURLs{"https://hooks.example.com/skret"}, cfg.Notify.WebhookURLs)
	assert.Equal(t, "top-signing-key", cfg.Notify.Secret)
	assert.Equal(t, []string{"set", "delete"}, cfg.Notify.Events)

	listed := `
version: "1"
environments:
  dev:
    provider: local
    file: secrets.yaml
notify:
  webhook_url:
    - https://hooks.example.com/a
    - https://hooks.example.com/b
`
	cfg, err = config.Load(writeTempConfig(t, listed))
	require.NoError(t, err)
	assert.Equal(t, config.WebhookURLs{
		"https://hooks.example.com/a",
		"https://hooks.example.com/b",
	}, cfg.Notify.WebhookURLs)
}

// TestNotifyConfig_AbsentIsNil pins the off-by-default contract: no notify
// block means cfg.Notify is nil and nothing fires.
func TestNotifyConfig_AbsentIsNil(t *testing.T) {
	raw := `
version: "1"
environments:
  dev:
    provider: local
    file: secrets.yaml
`
	cfg, err := config.Load(writeTempConfig(t, raw))
	require.NoError(t, err)
	assert.Nil(t, cfg.Notify)
}

func TestNotifyConfig_Validation_Rejections(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "empty webhook_url",
			raw: `notify:
  webhook_url: ""
`,
			want: "notify.webhook_url is required",
		},
		{
			name: "non-http scheme",
			raw: `notify:
  webhook_url: ftp://hooks.example.com/skret
`,
			want: "must be an absolute http(s) URL",
		},
		{
			name: "no host",
			raw: `notify:
  webhook_url: not-a-url
`,
			want: "must be an absolute http(s) URL",
		},
		{
			name: "unknown event",
			raw: `notify:
  webhook_url: https://hooks.example.com/skret
  events:
    - delte
`,
			want: `notify.events "delte" is not a known event`,
		},
		{
			name: "wrong node kind",
			raw: `notify:
  webhook_url:
    a: b
`,
			want: "must be a URL or a list of URLs",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := "version: \"1\"\nenvironments:\n  dev:\n    provider: local\n    file: secrets.yaml\n" + tc.raw
			_, err := config.Load(writeTempConfig(t, raw))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestNotifyConfig_ResolveCarriesNotify proves the resolved config hands the
// notify block to commands without a second config-file load.
func TestNotifyConfig_ResolveCarriesNotify(t *testing.T) {
	raw := `
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
notify:
  webhook_url: https://hooks.example.com/skret
`
	cfg, err := config.Load(writeTempConfig(t, raw))
	require.NoError(t, err)

	resolved, err := config.Resolve(cfg, config.ResolveOpts{})
	require.NoError(t, err)
	require.NotNil(t, resolved.Notify)
	assert.Equal(t, config.WebhookURLs{"https://hooks.example.com/skret"}, resolved.Notify.WebhookURLs)
}

// writeTempConfig writes raw into a temp .skret.yaml and returns the path.
func writeTempConfig(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".skret.yaml")
	require.NoError(t, os.WriteFile(path, []byte(raw), 0o644))
	return path
}
