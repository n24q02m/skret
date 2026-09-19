package config

import (
	"fmt"
	"net/url"

	"gopkg.in/yaml.v3"
)

// Config is the root schema for .skret.yaml.
type Config struct {
	Version      string                 `yaml:"version"`
	DefaultEnv   string                 `yaml:"default_env"`
	Project      string                 `yaml:"project"`
	Environments map[string]Environment `yaml:"environments"`
	Required     []string               `yaml:"required"`
	Exclude      []string               `yaml:"exclude"`
	Sync         *SyncConfig            `yaml:"sync,omitempty"`
	Notify       *NotifyConfig          `yaml:"notify,omitempty"`
}

// Environment defines provider configuration for one environment.
type Environment struct {
	Provider string `yaml:"provider"`
	Path     string `yaml:"path,omitempty"`
	Region   string `yaml:"region,omitempty"`
	Profile  string `yaml:"profile,omitempty"`
	KMSKeyID string `yaml:"kms_key_id,omitempty"`
	File     string `yaml:"file,omitempty"`
	// Encrypted declares write-side intent for the local provider: when
	// true, the provider stores the file as a keystore envelope (see
	// internal/keystore). Reads auto-detect an envelope on disk regardless
	// of this flag, so a plaintext file keeps working until
	// `skret keys init --encrypt-existing` migrates it.
	Encrypted bool `yaml:"encrypted,omitempty"`
}

// SyncConfig declares reusable sync routes (targets) + optional hub endpoint.
type SyncConfig struct {
	Targets []SyncTarget `yaml:"targets"`
	Hub     *HubConfig   `yaml:"hub,omitempty"`
}

// SyncTarget is one declared sync destination.
type SyncTarget struct {
	Type    string `yaml:"type"`              // github | cloudflare | dotenv
	Repo    string `yaml:"repo,omitempty"`    // github
	Worker  string `yaml:"worker,omitempty"`  // cloudflare worker script
	Pages   string `yaml:"pages,omitempty"`   // cloudflare pages project
	Account string `yaml:"account,omitempty"` // cloudflare account id
	File    string `yaml:"file,omitempty"`    // dotenv
	// NoOverwrite makes sync only write keys absent at this target; existing
	// keys are never overwritten (rotation = delete at target, next sync
	// repopulates from the provider). The --no-overwrite CLI flag forces this
	// for every target of a run.
	NoOverwrite bool `yaml:"no_overwrite,omitempty"`
	// BaseURL overrides the target's API endpoint (GitHub Enterprise, tests).
	// The github factory already consumes Fields["base_url"] (github.go:231);
	// this exposes it from yaml.
	BaseURL string `yaml:"base_url,omitempty"`
}

// NotifyEvent* name the mutation events skret can report to webhooks. They
// live in config (not internal/notify) so .skret.yaml validation and the
// webhook payload vocabulary share one source of truth.
const (
	NotifyEventSet    = "set"
	NotifyEventDelete = "delete"
	NotifyEventRotate = "rotate"
	NotifyEventSync   = "sync"
)

// notifyEventValid is the closed set of names accepted by notify.events.
var notifyEventValid = map[string]bool{
	NotifyEventSet:    true,
	NotifyEventDelete: true,
	NotifyEventRotate: true,
	NotifyEventSync:   true,
}

// ValidNotifyEvent reports whether name is a known mutation event.
func ValidNotifyEvent(name string) bool { return notifyEventValid[name] }

// NotifyConfig configures webhook notifications fired after successful
// secret mutations (set/delete/rotate/sync). The feature is off unless the
// notify block declares webhook_url. Payloads carry key names and event
// metadata only -- secret values are never included.
type NotifyConfig struct {
	// WebhookURLs accepts one URL or a YAML list of URLs (see WebhookURLs).
	WebhookURLs WebhookURLs `yaml:"webhook_url"`
	// Events optionally filters which mutation events fire; empty means all.
	Events []string `yaml:"events,omitempty"`
	// Secret, when set, signs each request body with HMAC-SHA256 in the
	// X-Skret-Signature header ("sha256=<hex>"). Receivers verify the raw
	// request body against this key.
	Secret string `yaml:"secret,omitempty"`
}

// WebhookURLs decodes `webhook_url` as either a scalar URL or a YAML
// sequence of URLs, so a single receiver stays the one-line config and a
// fan-out to several receivers needs no second key.
type WebhookURLs []string

func (w *WebhookURLs) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		var urls []string
		if err := node.Decode(&urls); err != nil {
			return fmt.Errorf("config: notify.webhook_url list: %w", err)
		}
		*w = urls
	case yaml.ScalarNode:
		var single string
		if err := node.Decode(&single); err != nil {
			return fmt.Errorf("config: notify.webhook_url: %w", err)
		}
		if single == "" {
			*w = nil
		} else {
			*w = []string{single}
		}
	default:
		return fmt.Errorf("config: notify.webhook_url must be a URL or a list of URLs")
	}
	return nil
}

func (n *NotifyConfig) validate() error {
	if len(n.WebhookURLs) == 0 {
		return fmt.Errorf("config: notify.webhook_url is required when the notify block is present")
	}
	for _, raw := range n.WebhookURLs {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("config: notify.webhook_url %q must be an absolute http(s) URL", raw)
		}
	}
	for _, e := range n.Events {
		if !ValidNotifyEvent(e) {
			return fmt.Errorf("config: notify.events %q is not a known event (known: set, delete, rotate, sync)", e)
		}
	}
	return nil
}

// HubConfig points at the vault dashboard manifest endpoint.
type HubConfig struct {
	URL string `yaml:"url"`
}

// Validate checks structural requirements: version, that at least one
// environment is declared, that default_env (if set) points at a real
// entry, and sync target shape. Per-provider requirement checks (does THIS
// environment have what its provider needs -- aws needs path, local needs
// file, unknown providers are rejected) are deliberately NOT done here:
// they run once, in Resolve() (resolver.go), scoped to only the
// environment actually selected. This fixes audit finding C1 root cause 2:
// Load() used to call Validate() before --env/default_env was even
// consulted, so a second, still-incomplete environment blocked every
// command that only ever touched a different, already-working one.
func (c *Config) Validate() error {
	if c.Version == "" {
		return fmt.Errorf("config: version is required")
	}
	if c.Version != "1" {
		return fmt.Errorf("config: unsupported version %q (expected \"1\")", c.Version)
	}
	if len(c.Environments) == 0 {
		return fmt.Errorf("config: at least one environment is required in environments")
	}
	if c.DefaultEnv != "" {
		if _, ok := c.Environments[c.DefaultEnv]; !ok {
			return fmt.Errorf("config: default_env %q not found in environments", c.DefaultEnv)
		}
	}
	if c.Sync != nil {
		for i := range c.Sync.Targets {
			if err := c.Sync.Targets[i].validate(); err != nil {
				return err
			}
		}
	}
	if c.Notify != nil {
		if err := c.Notify.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (e *Environment) validate(name string) error {
	if e.Provider == "" {
		return fmt.Errorf("config: environment %q: provider is required", name)
	}
	switch e.Provider {
	case "aws":
		if e.Path == "" {
			return fmt.Errorf("config: environment %q: path is required for aws provider", name)
		}
	case "local":
		if e.File == "" {
			return fmt.Errorf("config: environment %q: file is required for local provider", name)
		}
	default:
		return fmt.Errorf("config: environment %q: unknown provider %q", name, e.Provider)
	}
	return nil
}

func (s *SyncTarget) validate() error {
	switch s.Type {
	case "github":
		if s.Repo == "" {
			return fmt.Errorf("config: github sync target: repo is required")
		}
	case "cloudflare":
		if s.Worker == "" && s.Pages == "" {
			return fmt.Errorf("config: cloudflare sync target: worker or pages is required")
		}
		if s.Worker != "" && s.Pages != "" {
			return fmt.Errorf("config: cloudflare sync target: set exactly one of worker/pages")
		}
	case "dotenv":
		// file optional (defaults to .env at build time)
	default:
		return fmt.Errorf("config: unknown sync target type %q", s.Type)
	}
	return nil
}
