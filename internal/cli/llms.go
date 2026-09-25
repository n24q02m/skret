package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/n24q02m/skret/internal/version"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// llms.go implements `skret llms` — a names-only capability manifest in the
// llms.txt style, meant to be pasted into an LLM session as in-context
// documentation. It is generated from live sources wherever one exists:
//
//   - commands + flags: the actual cobra command tree (cmd.Root() at run
//     time), so a new subcommand or flag shows up without touching this file
//   - providers: the provider registry (defaultRegistry().Providers())
//   - exit codes: the pkg/skret constants, referenced so a rename breaks the
//     build instead of drifting
//
// The env-var and config-key tables are curated here (no runtime registry
// exists for them); llms_test.go pins them to the source trees by scanning
// os.Getenv("SKRET_...") call sites and schema.go yaml tags respectively, so
// adding a new one without updating the manifest fails CI.
//
// Contract: stdout carries data only, output is deterministic (byte-exact
// across runs), fully non-interactive, never reads config or key material,
// and never includes secret names or values.

// llmsCommand is one entry of the manifest's commands section.
type llmsCommand struct {
	Command string   `json:"command"`
	Short   string   `json:"short"`
	Flags   []string `json:"flags"`
}

// llmsNamed is one name/description row (env vars and config keys).
type llmsNamed struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// llmsManifest is the --format json payload. Field set is fixed by the
// spec: {version, commands[], providers[], exit_codes{}, env_vars[],
// config_keys[]}.
type llmsManifest struct {
	Version    string            `json:"version"`
	Commands   []llmsCommand     `json:"commands"`
	Providers  []string          `json:"providers"`
	ExitCodes  map[string]string `json:"exit_codes"`
	EnvVars    []llmsNamed       `json:"env_vars"`
	ConfigKeys []llmsNamed       `json:"config_keys"`
}

type llmsOptions struct {
	format string
}

func newLLMsCmd() *cobra.Command {
	o := &llmsOptions{}

	cmd := &cobra.Command{
		Use:   "llms",
		Short: "Print a names-only capability manifest for LLM agents (llms.txt style)",
		Long: `Print a names-only capability manifest an LLM agent can paste into
its session as in-context documentation: the command list with flags,
supported providers, exit-code table, environment variables, and
.skret.yaml config keys.

Generated from the live command tree and provider registry. Names only:
secret names and values are never included, nothing is read from config
or key material, and the output is deterministic so it can be diffed or
snapshotted.

stdout carries data only; the run is fully non-interactive and exits 0.`,
		Example: `  skret llms
  skret llms --format json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}

	cmd.Flags().StringVar(&o.format, "format", "table", "output format (table, json)")

	return cmd
}

func (o *llmsOptions) run(cmd *cobra.Command) error {
	if o.format != "table" && o.format != "json" {
		return skret.NewError(skret.ExitValidationError,
			fmt.Sprintf("llms: unknown --format %q (table, json)", o.format), nil)
	}
	manifest := buildLLMsManifest(cmd.Root())
	stdout := cmd.OutOrStdout()

	if o.format == "json" {
		data, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return skret.NewError(skret.ExitGenericError, "llms: encode manifest", err)
		}
		fmt.Fprintln(stdout, string(data))
		return nil
	}

	return renderLLMsText(stdout, manifest)
}

var buildLLMsManifestExitCodes map[string]string

func init() {
	buildLLMsManifestExitCodes = make(map[string]string, len(llmsExitCodeTable))
	for _, row := range llmsExitCodeTable {
		buildLLMsManifestExitCodes[strconv.Itoa(row.code)] = row.Constant + " — " + row.Meaning
	}
}

// buildLLMsManifest assembles the manifest from the live command tree, the
// provider registry, and the curated tables below.
func buildLLMsManifest(root *cobra.Command) llmsManifest {
	providers := defaultRegistry().Providers()
	return llmsManifest{
		Version:    version.Version,
		Commands:   llmsCommandRows(root),
		Providers:  providers,
		ExitCodes:  buildLLMsManifestExitCodes,
		EnvVars:    llmsEnvVarRows(),
		ConfigKeys: llmsConfigKeyRows(),
	}
}

// llmsCommandRows walks the command tree depth-first and renders one row per
// visible command, sorted by full command path. Flags are the command's own
// (local) flags, names only, in pflag's lexical order; global persistent
// flags are listed once on the root row.
func llmsCommandRows(root *cobra.Command) []llmsCommand {
	var rows []llmsCommand
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Hidden {
			return
		}
		var flags []string
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if !f.Hidden {
				flags = append(flags, "--"+f.Name)
			}
		})
		if flags == nil {
			flags = []string{}
		}
		rows = append(rows, llmsCommand{
			Command: c.CommandPath(),
			Short:   c.Short,
			Flags:   flags,
		})
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Command < rows[j].Command })
	return rows
}

// llmsExitCodeRow is one exit-code table entry. code carries the pkg/skret
// constant so a rename or renumber there breaks the build here.
type llmsExitCodeRow struct {
	code     int
	Constant string
	Meaning  string
}

// llmsExitCodeTable mirrors the Error Codes reference (docs
// reference/error-codes.md) and guide/agents.md. Keep all three in step.
var llmsExitCodeTable = []llmsExitCodeRow{
	{skret.ExitSuccess, "ExitSuccess", "operation completed successfully"},
	{skret.ExitGenericError, "ExitGenericError", "unclassified error"},
	{skret.ExitConfigError, "ExitConfigError", ".skret.yaml missing or invalid"},
	{skret.ExitProviderError, "ExitProviderError", "backend provider call failed"},
	{skret.ExitAuthError, "ExitAuthError", "authentication failed"},
	{skret.ExitNotFoundError, "ExitNotFoundError", "secret does not exist"},
	{skret.ExitConflictError, "ExitConflictError", "key already exists (--on-conflict=fail)"},
	{skret.ExitNetworkError, "ExitNetworkError", "network/connectivity failure"},
	{skret.ExitValidationError, "ExitValidationError", "invalid input or flag value"},
	{skret.ExitDrift, "ExitDrift", "skret diff --exit-code found a difference"},
	{skret.ExitLeakFound, "ExitLeakFound", "skret scan found a managed secret value in a scanned file"},
	{skret.ExitExecError, "ExitExecError", "skret run -- could not exec the command"},
}

// llmsEnvVarTable documents the SKRET_* environment variables skret reads.
// llms_test.go scans the source tree for SKRET_ usages and fails when a
// variable is read somewhere but missing here.
var llmsEnvVarTable = []llmsNamed{
	{"SKRET_ACTOR", "audit-trail actor name override (use a bot identity in CI)"},
	{"SKRET_AGE_KEY", "age identity for local-provider encryption (alternative to 'skret keys init')"},
	{"SKRET_ENV", "default environment override"},
	{"SKRET_EXPERIMENTAL", "set to 1 to enable experimental commands (history, rollback)"},
	{"SKRET_HUB_TOKEN", "bearer token for 'skret hub' pushes"},
	{"SKRET_HUB_URL", "hub endpoint URL override (after --hub-url, before sync.hub.url)"},
	{"SKRET_KEYRING", "set to keyring to opt in to OS-keyring credential storage"},
	{"SKRET_LOCAL_KEY", "alternative local-provider key material (consulted after SKRET_AGE_KEY)"},
	{"SKRET_LOG", "log level: debug, info, warn, error (default info)"},
	{"SKRET_LOG_FORMAT", "log output format override"},
	{"SKRET_NON_INTERACTIVE", "set to 1 to fail instead of prompting"},
	{"SKRET_NO_BROWSER", "suppress automatic browser launch during auth flows"},
	{"SKRET_OPERATOR_SESSION_COOKIE", "operator UI session cookie for hub authentication"},
	{"SKRET_PATH", "secret path prefix override"},
	{"SKRET_PROFILE", "cloud profile override"},
	{"SKRET_PROVIDER", "provider override"},
	{"SKRET_REGION", "cloud region override"},
}

func llmsEnvVarRows() []llmsNamed {
	rows := append([]llmsNamed(nil), llmsEnvVarTable...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows
}

// llmsConfigKeyTable documents the .skret.yaml keys (the yaml tags of
// internal/config/schema.go, flat: the description says where a key nests).
// llms_test.go parses the yaml tags out of schema.go and fails when one is
// missing here.
var llmsConfigKeyTable = []llmsNamed{
	{"account", "sync target: cloudflare account id (sync.targets[].account)"},
	{"allow_write", "mcp: enable the skret-mcp write tools (skret_set/delete/rotate); default false (mcp.allow_write)"},
	{"allowed_envs", "mcp: restrict which environments the skret-mcp server may access (mcp.allowed_envs)"},
	{"audit_log", "environment: path of the local audit JSONL trail (environments.<env>.audit_log)"},
	{"base_url", "sync target: API endpoint override, e.g. GitHub Enterprise (sync.targets[].base_url)"},
	{"compartment_id", "environment: OCI compartment OCID (environments.<env>.compartment_id)"},
	{"default_env", "environment used when none is specified via --env or SKRET_ENV"},
	{"encrypted", "environment: at-rest encryption intent for the local provider (environments.<env>.encrypted)"},
	{"environments", "map of environment name to per-environment settings"},
	{"events", "notify: mutation events that fire a webhook (set, delete, rotate, sync); empty means all"},
	{"exclude", "secret key names to exclude from operations"},
	{"file", "environment/sync target: local secrets file (environments.<env>.file, dotenv/terraform/k8s targets)"},
	{"hub", "sync: hub endpoint for 'skret hub' state pushes (sync.hub)"},
	{"key_id", "environment: OCI key OCID for vault encryption (environments.<env>.key_id)"},
	{"kms_key_id", "environment: AWS KMS customer-managed key (environments.<env>.kms_key_id)"},
	{"masked", "sync target: mark GitLab CI/CD variables masked (sync.targets[].masked)"},
	{"mcp", "policy for the skret-mcp MCP server: write gating and environment access (mcp)"},
	{"name", "sync target: metadata.name of the generated k8s Secret (sync.targets[].name)"},
	{"namespace", "sync target: metadata.namespace of the generated k8s Secret (sync.targets[].namespace)"},
	{"no_overwrite", "sync target: only write keys absent at the target (sync.targets[].no_overwrite)"},
	{"notify", "webhook notifications fired after successful mutations"},
	{"pages", "sync target: cloudflare pages project (sync.targets[].pages)"},
	{"path", "environment: secret path prefix (environments.<env>.path)"},
	{"profile", "environment: cloud profile (environments.<env>.profile)"},
	{"project", "informational project name; also the GitLab project (id or group/project) on sync targets"},
	{"provider", "environment: backend provider: aws, local, gcp, azure, oci (environments.<env>.provider)"},
	{"protected", "sync target: mark GitLab CI/CD variables protected, i.e. only exposed to protected branches/tags (sync.targets[].protected)"},
	{"region", "environment: cloud region (environments.<env>.region)"},
	{"repo", "sync target: GitHub repository (sync.targets[].repo)"},
	{"required", "secret key names that must exist"},
	{"secret", "notify: HMAC-SHA256 signing key for the X-Skret-Signature header (notify.secret)"},
	{"sync", "reusable sync destinations plus the optional hub endpoint"},
	{"targets", "sync: list of sync destination definitions (sync.targets[])"},
	{"type", "sync target: github, cloudflare, dotenv, gitlab, terraform, k8s (sync.targets[].type)"},
	{"url", "sync.hub.url: hub endpoint"},
	{"vault_id", "environment: OCI vault OCID (environments.<env>.vault_id)"},
	{"vault_name", "environment: Azure Key Vault name (environments.<env>.vault_name)"},
	{"vault_url", "environment: Azure Key Vault URL (environments.<env>.vault_url)"},
	{"version", "config schema version (\"1\")"},
	{"webhook_url", "notify: one webhook URL or a list of URLs (notify.webhook_url)"},
	{"worker", "sync target: cloudflare worker script (sync.targets[].worker)"},
}

func llmsConfigKeyRows() []llmsNamed {
	rows := append([]llmsNamed(nil), llmsConfigKeyTable...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows
}

// renderLLMsText writes the llms.txt-style manifest: one section per
// capability group, deterministic order, names only.
func renderLLMsText(w io.Writer, m llmsManifest) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# skret v%s — capability manifest\n\n", m.Version)
	b.WriteString("Names only: secret names and values are never included. Paste this into an LLM session as in-context documentation.\n\n")

	fmt.Fprintf(&b, "## Commands (%d)\n\n", len(m.Commands))
	for _, c := range m.Commands {
		fmt.Fprintf(&b, "%s — %s\n", c.Command, c.Short)
		if len(c.Flags) > 0 {
			fmt.Fprintf(&b, "  flags: %s\n", strings.Join(c.Flags, " "))
		}
	}

	fmt.Fprintf(&b, "\n## Providers (%d)\n\n", len(m.Providers))
	for _, p := range m.Providers {
		if dn, ok := providerDisplayNames[p]; ok {
			fmt.Fprintf(&b, "- %s — %s\n", p, dn)
		} else {
			fmt.Fprintf(&b, "- %s\n", p)
		}
	}

	codes := make([]string, 0, len(m.ExitCodes))
	for k := range m.ExitCodes {
		codes = append(codes, k)
	}
	sort.Slice(codes, func(i, j int) bool {
		a, _ := strconv.Atoi(codes[i])
		z, _ := strconv.Atoi(codes[j])
		return a < z
	})
	fmt.Fprintf(&b, "\n## Exit codes (%d)\n\n", len(m.ExitCodes))
	for _, k := range codes {
		fmt.Fprintf(&b, "%s %s\n", k, m.ExitCodes[k])
	}

	fmt.Fprintf(&b, "\n## Environment variables (%d)\n\n", len(m.EnvVars))
	for _, e := range m.EnvVars {
		fmt.Fprintf(&b, "%s — %s\n", e.Name, e.Description)
	}

	fmt.Fprintf(&b, "\n## Config keys (.skret.yaml) (%d)\n", len(m.ConfigKeys))
	for _, k := range m.ConfigKeys {
		fmt.Fprintf(&b, "%s — %s\n", k.Name, k.Description)
	}

	_, err := io.WriteString(w, b.String())
	return err
}
