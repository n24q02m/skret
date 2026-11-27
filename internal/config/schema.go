package config

import (
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"

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
	MCP          *MCPConfig             `yaml:"mcp,omitempty"`
}

// Environment defines provider configuration for one environment.
type Environment struct {
	Provider string `yaml:"provider"`
	Path     string `yaml:"path,omitempty"`
	Region   string `yaml:"region,omitempty"`
	Profile  string `yaml:"profile,omitempty"`
	KMSKeyID string `yaml:"kms_key_id,omitempty"`
	File     string `yaml:"file,omitempty"`
	// Project is the GCP project id for gcp environments. GOOGLE_CLOUD_PROJECT
	// (the standard ADC ambient) takes precedence when set.
	Project string `yaml:"project,omitempty"`
	// Encrypted declares write-side intent for the local provider: when
	// true, the provider stores the file as a keystore envelope (see
	// internal/keystore). Reads auto-detect an envelope on disk regardless
	// of this flag, so a plaintext file keeps working until
	// `skret keys init --encrypt-existing` migrates it.
	Encrypted bool `yaml:"encrypted,omitempty"`
	// AuditLog overrides the local provider's audit trail location. The
	// default is `.skret-audit.log` next to the secrets file. Mutations
	// (set/rotate/delete) append one JSONL line per change recording names
	// and metadata only -- never values.
	AuditLog string `yaml:"audit_log,omitempty"`
	// CompartmentID is the OCID of the compartment holding the vault for
	// the oci provider.
	CompartmentID string `yaml:"compartment_id,omitempty"`
	// VaultID is the OCID of the OCI vault where secrets live for the oci
	// provider.
	VaultID string `yaml:"vault_id,omitempty"`
	// KeyID is the OCID of the software-protected master encryption key
	// used when the oci provider creates a new secret (updates reuse the
	// secret's existing key).
	KeyID string `yaml:"key_id,omitempty"`
	// Azure Key Vault endpoint. One of vault_url or vault_name is required
	// for the azure provider; vault_name derives
	// https://<name>.vault.azure.net. Setting both requires them to agree.
	VaultURL  string `yaml:"vault_url,omitempty"`
	VaultName string `yaml:"vault_name,omitempty"`
}

// SyncConfig declares reusable sync routes (targets) + optional hub endpoint.
type SyncConfig struct {
	Targets []SyncTarget `yaml:"targets"`
	Hub     *HubConfig   `yaml:"hub,omitempty"`
}

// SyncTarget is one declared sync destination.
type SyncTarget struct {
	Type    string `yaml:"type"`              // github | cloudflare | dotenv | gitlab | terraform | k8s (alias: k8s-manifest)
	Repo    string `yaml:"repo,omitempty"`    // github
	Worker  string `yaml:"worker,omitempty"`  // cloudflare worker script
	Pages   string `yaml:"pages,omitempty"`   // cloudflare pages project
	Account string `yaml:"account,omitempty"` // cloudflare account id
	File    string `yaml:"file,omitempty"`    // dotenv, terraform, k8s
	// Project is the GitLab project (numeric id or group/project path) for
	// gitlab targets.
	Project string `yaml:"project,omitempty"`
	// Masked marks gitlab CI/CD variables as masked. The value must satisfy
	// GitLab masking requirements or the API rejects the write.
	Masked bool `yaml:"masked,omitempty"`
	// Protected marks gitlab CI/CD variables as protected (only available to
	// protected branches/tags).
	Protected bool `yaml:"protected,omitempty"`
	// Name is metadata.name of the generated k8s Secret (default
	// skret-secrets).
	Name string `yaml:"name,omitempty"`
	// Namespace, when set, is emitted as metadata.namespace of the generated
	// k8s Secret.
	Namespace string `yaml:"namespace,omitempty"`
	// NoOverwrite makes sync only write keys absent at this target; existing
	// keys are never overwritten (rotation = delete at target, next sync
	// repopulates from the provider). The --no-overwrite CLI flag forces this
	// for every target of a run.
	NoOverwrite bool `yaml:"no_overwrite,omitempty"`
	// BaseURL overrides the target's API endpoint (GitHub Enterprise, tests).
	// The github factory already consumes Fields["base_url"] (github.go:231);
	// this exposes it from yaml.
	BaseURL string `yaml:"base_url,omitempty"`
	// Sources, when set, replaces the environment path as this target's
	// source set: the target receives the union of every source, and
	// --prune compares the target against that union. Without Sources the
	// target syncs the environment path exactly as before, and --prune
	// refuses it so a prune baseline is never left implicit.
	Sources []SyncSource `yaml:"sources,omitempty"`
}

// SyncSource is one provider path feeding a sync target. Path defaults to
// the environment path. Keys keeps only the listed env-var names (each must
// exist); Exclude drops the listed names. A source sets at most one of the
// two. The top-level exclude list applies to every source as well.
type SyncSource struct {
	Path    string   `yaml:"path,omitempty"`
	Keys    []string `yaml:"keys,omitempty"`
	Exclude []string `yaml:"exclude,omitempty"`
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

// MCPConfig configures the skret-mcp server surface (cmd/skret-mcp). The
// block is optional; when absent the server runs with the defaults below.
type MCPConfig struct {
	// AllowWrite enables the mutating MCP tools (skret_set/skret_delete/
	// skret_rotate). Default false: the server exposes only read tools and
	// a write tool call returns an error naming this field.
	AllowWrite bool `yaml:"allow_write,omitempty"`
	// AllowedEnvs restricts which .skret.yaml environments the server may
	// access. Empty means every declared environment. Names must reference
	// declared environments (validated in Config.Validate).
	AllowedEnvs []string `yaml:"allowed_envs,omitempty"`
	// AllowedTools restricts which MCP tools the server lists and runs.
	// Empty means every tool. Entries must name a tool from MCPToolNames.
	// It narrows the tool set only: a write tool still needs allow_write.
	AllowedTools []string `yaml:"allowed_tools,omitempty"`
	// AllowedKeys restricts which secret keys the MCP tools may read,
	// list, or mutate. Entries are path.Match glob patterns matched against
	// the whole key name (case-sensitive; `*` does not cross `/`). Empty
	// means every key.
	AllowedKeys []string `yaml:"allowed_keys,omitempty"`
	// DeniedKeys blocks secret keys from every MCP tool. Same glob syntax
	// as AllowedKeys; a key matching any entry is denied even when it also
	// matches AllowedKeys.
	DeniedKeys []string `yaml:"denied_keys,omitempty"`
	// AuditLog, when set, appends the MCP session audit trail (one JSON
	// line per tool call, also written to stderr) to this file. A relative
	// path is anchored at the config directory (see AnchorToDir).
	AuditLog string `yaml:"audit_log,omitempty"`
}

// mcpToolNames is the closed set of tools the skret-mcp server exposes, in
// tools/list order. mcp.allowed_tools entries are validated against it, and
// the server's own tool table is tested against it so the two cannot drift.
var mcpToolNames = []string{
	"skret_list", "skret_get", "skret_env", "skret_status", "skret_doctor",
	"skret_set", "skret_delete", "skret_rotate",
}

// MCPToolNames returns a copy of the closed MCP tool set, in tools/list
// order.
func MCPToolNames() []string { return slices.Clone(mcpToolNames) }

// ValidMCPTool reports whether name is a tool the skret-mcp server exposes.
func ValidMCPTool(name string) bool { return slices.Contains(mcpToolNames, name) }

// validate checks the mcp block against the rest of the config:
// allowed_envs names must reference declared environments and
// allowed_tools names must reference real tools (a typo would otherwise
// silently lock the MCP server out), and the key filters must be valid
// glob patterns (an unparsable pattern would otherwise never match).
func (m *MCPConfig) validate(envs map[string]Environment) error {
	for _, name := range m.AllowedEnvs {
		if _, ok := envs[name]; !ok {
			return fmt.Errorf("config: mcp.allowed_envs entry %q not found in environments", name)
		}
	}
	for _, name := range m.AllowedTools {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("config: mcp.allowed_tools has an empty entry")
		}
		if !ValidMCPTool(name) {
			return fmt.Errorf("config: mcp.allowed_tools entry %q is not a known tool (known: %s)", name, strings.Join(mcpToolNames, ", "))
		}
	}
	if err := validateKeyPatterns("allowed_keys", m.AllowedKeys); err != nil {
		return err
	}
	return validateKeyPatterns("denied_keys", m.DeniedKeys)
}

// validateKeyPatterns rejects empty entries and patterns path.Match cannot
// parse. path.Match reports a malformed pattern even against an empty name,
// so one probe per entry validates the whole pattern.
func validateKeyPatterns(field string, patterns []string) error {
	for _, p := range patterns {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("config: mcp.%s has an empty entry", field)
		}
		if _, err := path.Match(p, ""); err != nil {
			return fmt.Errorf("config: mcp.%s entry %q is not a valid glob pattern: %w", field, p, err)
		}
	}
	return nil
}

// HubConfig points at the vault dashboard manifest endpoint.
type HubConfig struct {
	URL string `yaml:"url"`
	// Namespace pins the manifest namespace `hub push` publishes under,
	// overriding the default (the resolved environment path). Written by
	// `skret hub init`; optional -- when empty, hub push falls back to the
	// environment path so existing configs keep their current namespace.
	Namespace string `yaml:"namespace,omitempty"`
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
	if c.MCP != nil {
		if err := c.MCP.validate(c.Environments); err != nil {
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
	case "gcp":
		if e.Project == "" {
			return fmt.Errorf("config: environment %q: project is required for gcp provider", name)
		}
		if e.Path != "" {
			return fmt.Errorf("config: environment %q: path must be empty for gcp provider (GCP secret ids are flat; use one GCP project per environment)", name)
		}
	case "local":
		if e.File == "" {
			return fmt.Errorf("config: environment %q: file is required for local provider", name)
		}
	case "azure":
		if e.VaultURL == "" && e.VaultName == "" {
			return fmt.Errorf("config: environment %q: one of vault_url or vault_name is required for azure provider", name)
		}
	case "oci":
		if e.CompartmentID == "" {
			return fmt.Errorf("config: environment %q: compartment_id is required for oci provider", name)
		}
		if e.VaultID == "" {
			return fmt.Errorf("config: environment %q: vault_id is required for oci provider", name)
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
	case "gitlab":
		if s.Project == "" {
			return fmt.Errorf("config: gitlab sync target: project is required")
		}
	case "terraform":
		// file optional (defaults to terraform.tfvars at build time)
	case "k8s", "k8s-manifest":
		// file optional (defaults to stdout); name/namespace shape is
		// validated at build time by the syncer factory
	case "dotenv":
		// file optional (defaults to .env at build time)
	default:
		return fmt.Errorf("config: unknown sync target type %q", s.Type)
	}
	return validateSyncSources(s.Type, s.Sources)
}

// validateSyncSources rejects source lists whose meaning is ambiguous. Two
// sources resolving to the same path would read the same keys twice, so the
// comparison ignores a trailing slash and treats an empty path as the
// environment path.
func validateSyncSources(typ string, sources []SyncSource) error {
	if sources == nil {
		return nil
	}
	if len(sources) == 0 {
		return fmt.Errorf("config: %s sync target: sources is empty; omit it to sync the environment path", typ)
	}
	seen := make(map[string]bool, len(sources))
	for i := range sources {
		src := &sources[i]
		if len(src.Keys) > 0 && len(src.Exclude) > 0 {
			return fmt.Errorf("config: %s sync target: source %d sets both keys and exclude", typ, i)
		}
		for _, k := range src.Keys {
			if strings.TrimSpace(k) == "" {
				return fmt.Errorf("config: %s sync target: source %d has an empty key", typ, i)
			}
		}
		for _, e := range src.Exclude {
			if strings.TrimSpace(e) == "" {
				return fmt.Errorf("config: %s sync target: source %d has an empty exclude entry", typ, i)
			}
		}
		trimmed := src.Path
		for len(trimmed) > 1 && strings.HasSuffix(trimmed, "/") {
			trimmed = trimmed[:len(trimmed)-1]
		}
		if seen[trimmed] {
			label := src.Path
			if label == "" {
				label = "(environment path)"
			}
			return fmt.Errorf("config: %s sync target: duplicate source path %q", typ, label)
		}
		seen[trimmed] = true
	}
	return nil
}
