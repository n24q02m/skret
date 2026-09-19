package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/syncer"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

type hubOptions struct {
	global    *GlobalOpts
	hubURL    string
	url       string
	namespace string
}

func newHubCmd(opts *GlobalOpts) *cobra.Command {
	o := &hubOptions{global: opts}
	cmd := &cobra.Command{
		Use:   "hub",
		Short: "Publish secret inventory to the vault dashboard",
		Long: "Groups subcommands that publish secret inventory to the vault dashboard.\n\n" +
			"'hub init' writes the sync.hub config block, 'hub push' sends a names-only " +
			"manifest (no values), and 'hub status' reports what the hub currently holds.",
	}
	push := &cobra.Command{
		Use:   "push",
		Short: "Push a names-only manifest (no values) to the hub",
		Long: `Publish a names-only inventory (manifest) to the vault dashboard.

The manifest contains key names, a salted sha256[:8] fingerprint, and a
per-target presence status (present/absent/unknown) — never secret values.
Presence is looked up live: for each declared sync.targets entry whose
syncer can enumerate existing names (github, cloudflare worker), hub push
calls that target's API once per push. Targets that cannot enumerate
(dotenv, a Cloudflare Pages target) or whose lookup fails always report
"unknown" for every key, with a warning on stderr in the failure case --
one target's problem never fails the whole push. Auth via SKRET_HUB_TOKEN;
the endpoint comes from --hub-url, the SKRET_HUB_URL env var, or
sync.hub.url in .skret.yaml (in that order). The manifest namespace is
sync.hub.namespace when set, else the resolved environment path. A live
presence check needs the same target credentials as 'skret sync'
(GITHUB_TOKEN / CLOUDFLARE_API_TOKEN); the cron sync container already
forwards them, a manual/laptop run must export them itself.`,
		Example: `  skret hub push
  skret hub push --hub-url https://vault.example.com`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.runPush(cmd)
		},
	}
	push.Flags().StringVar(&o.hubURL, "hub-url", "", "hub base URL (overrides sync.hub.url)")
	cmd.AddCommand(push)

	init := &cobra.Command{
		Use:   "init",
		Short: "Write the sync.hub config block into .skret.yaml",
		Long: `Write the sync.hub block (hub URL and manifest namespace) into
.skret.yaml so a bare 'skret hub push' / 'skret hub status' knows where to
talk. The namespace defaults to the resolved environment path; pass
--namespace to pin a different one. The URL is required -- the CLI never
guesses an endpoint. Writes atomically with a .bak backup (the init
convention); re-running with the same values reports "unchanged" and
leaves the file untouched.`,
		Example: `  skret hub init --url https://vault.example.com
  skret hub init --url https://vault.example.com --namespace /myapp/prod`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.runInit(cmd)
		},
	}
	init.Flags().StringVar(&o.url, "url", "", "hub base URL to store in sync.hub.url (required)")
	init.Flags().StringVar(&o.namespace, "namespace", "", "manifest namespace to store in sync.hub.namespace (default: the resolved environment path)")
	_ = init.MarkFlagRequired("url")
	cmd.AddCommand(init)

	status := &cobra.Command{
		Use:   "status",
		Short: "Report hub reachability and per-namespace manifest stats",
		Long: `Ask the hub's /api/status endpoint (same bearer token as push) what
it currently holds: per-namespace key counts and manifest freshness. The
endpoint comes from --hub-url, the SKRET_HUB_URL env var, or sync.hub.url
in .skret.yaml (in that order). Auth via SKRET_HUB_TOKEN; the hub answers
401 without it. Names-only: the response carries counts and timestamps,
never key names or secret values.`,
		Example: `  skret hub status
  skret hub status --hub-url https://vault.example.com --format json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.runStatus(cmd)
		},
	}
	status.Flags().StringVar(&o.hubURL, "hub-url", "", "hub base URL (overrides sync.hub.url)")
	cmd.AddCommand(status)
	return cmd
}

func (o *hubOptions) runPush(cmd *cobra.Command) error {
	resolved, p, err := loadProvider(o.global)
	if err != nil {
		return err
	}
	defer p.Close()
	warnIfPathMangled(cmd, resolved)

	sc, err := loadSyncConfig(o.global)
	if err != nil {
		return skret.NewError(skret.ExitConfigError, "hub push: load config failed", err)
	}

	// Resolve the hub endpoint with flag > env > config precedence. The env
	// fallback (SKRET_HUB_URL) is what lets the cron sync container point
	// `skret hub push` at the vault Worker via a forwarded env var, with no
	// flag and no baked config.
	hubURL, err := resolveHubURL(o.hubURL, sc)
	if err != nil {
		return skret.NewError(skret.ExitConfigError, "hub push: "+err.Error(), nil)
	}

	ctx := context.Background()
	secrets, err := p.List(ctx, resolved.Path)
	if err != nil {
		return skret.NewError(skret.ExitProviderError, "hub push: list secrets failed", err)
	}

	salt, err := syncer.LoadDeploySalt()
	if err != nil {
		return skret.NewError(skret.ExitGenericError, "hub push: load deploy salt failed", err)
	}

	presence := targetPresence(ctx, cmd, sc)
	// Namespace precedence: sync.hub.namespace (written by `hub init`)
	// overrides the resolved environment path, so a deployment can pin a
	// stable namespace even when it moves providers or paths.
	ns := resolved.Path
	if sc != nil && sc.Hub != nil && sc.Hub.Namespace != "" {
		ns = sc.Hub.Namespace
	}
	m := syncer.BuildManifest(ns, resolved.EnvName, salt, secrets, presence)
	m.GeneratedAt = time.Now().UTC()

	token := os.Getenv("SKRET_HUB_TOKEN")
	if err := postManifest(hubURL, token, m); err != nil {
		return skret.NewError(skret.ExitNetworkError, "hub push: post manifest failed", err)
	}
	cmd.PrintErrf("Pushed manifest: %d keys to %s\n", len(m.Keys), hubURL)
	return nil
}

// resolveHubURL applies the shared hub endpoint precedence -- explicit flag,
// then SKRET_HUB_URL, then sync.hub.url from .skret.yaml -- and rejects the
// none-of-the-above case with the fix in the message. Used by both `hub push`
// and `hub status` so the two can never disagree about where the hub is.
func resolveHubURL(flagVal string, sc *config.SyncConfig) (string, error) {
	hubURL := flagVal
	if hubURL == "" {
		hubURL = os.Getenv("SKRET_HUB_URL")
	}
	if hubURL == "" && sc != nil && sc.Hub != nil {
		hubURL = sc.Hub.URL
	}
	if hubURL == "" {
		return "", fmt.Errorf("no hub URL (set --hub-url, SKRET_HUB_URL, or sync.hub.url in .skret.yaml)")
	}
	return hubURL, nil
}

// targetPresence determines, for each declared sync target, which secret
// names already exist at that target -- by building the target's Syncer
// and calling ExistingKeys once (the same mechanism sync --no-overwrite
// uses via syncer.FilterAbsent). hub push never reads local sync-state:
// presence is always a live name-by-name check against the target itself.
//
// A target contributes an "unknown" (syncer.TargetPresence{}) entry, never
// an error that aborts the whole push, when:
//   - it cannot be built at all (e.g. a required token env var is unset) --
//     warned, since this is a real, fixable misconfiguration;
//   - its syncer type has no ExistingLister implementation (dotenv always;
//     cloudflare when it is a Pages target) -- silent, since this is a
//     structural limitation of the target type, not a failure;
//   - ExistingKeys itself returns an error (network/API failure, or a
//     Cloudflare Pages target, which satisfies ExistingLister but always
//     errors from inside ExistingKeys) -- warned.
func targetPresence(ctx context.Context, cmd *cobra.Command, sc *config.SyncConfig) map[string]syncer.TargetPresence {
	presence := map[string]syncer.TargetPresence{}
	if sc == nil {
		return presence
	}
	// Index rather than range-by-value: SyncTarget is large and gocritic's
	// rangeValCopy flags 176-byte-per-iteration copies.
	for i := range sc.Targets {
		t := &sc.Targets[i]
		tc := targetFromConfig(*t) // Task 5 helper: resolves Fields/Token from env
		key := t.Type + ":" + targetStateID(hubSyncerStub(t.Type), tc)

		syncers, err := syncer.Build([]syncer.TargetConfig{tc})
		if err != nil {
			cmd.PrintErrf("warning: hub push: %s: build target failed: %v\n", key, err)
			presence[key] = syncer.TargetPresence{}
			continue
		}
		lister, ok := syncers[0].(syncer.ExistingLister)
		if !ok {
			presence[key] = syncer.TargetPresence{} // e.g. dotenv: cannot enumerate
			continue
		}
		names, err := lister.ExistingKeys(ctx)
		if err != nil {
			cmd.PrintErrf("warning: hub push: %s: list existing keys failed: %v\n", key, err)
			presence[key] = syncer.TargetPresence{}
			continue
		}
		set := make(map[string]bool, len(names))
		for _, n := range names {
			set[strings.ToUpper(n)] = true
		}
		presence[key] = syncer.TargetPresence{Names: set, Ok: true}
	}
	return presence
}

// hubSyncerStub returns a syncer.Syncer of the requested type purely to
// resolve its Name() for targetStateID, ahead of (and independent from)
// whether syncer.Build succeeds for the real, fully-configured target --
// so the manifest key ("<type>:<id>") is stable even when a target fails
// to build (e.g. missing token) and falls back to "unknown".
func hubSyncerStub(typ string) syncer.Syncer {
	switch typ {
	case "github":
		return syncer.NewGitHub("", "", "", "")
	case "cloudflare":
		return syncer.NewCloudflare("", "", "", "", "")
	case "gitlab":
		return syncer.NewGitLab("", "", "", false, false)
	case "terraform":
		return syncer.NewTerraform("")
	case "k8s", syncer.K8sManifestAlias:
		return syncer.NewK8s("-", "", "")
	default:
		return syncer.NewDotenv("")
	}
}

// postManifest sends the names-only manifest to the hub's ingest endpoint.
// The request body is the JSON-encoded Manifest, which by construction
// (syncer.BuildManifest) never carries secret values — only names,
// fingerprints, and per-target presence status.
//
// If a bearer token is set, the hub URL is checked first: plain http to any
// host other than loopback would put SKRET_HUB_TOKEN on the wire in the
// clear, so that combination is refused before the request is built.
func postManifest(hubURL, token string, m *syncer.Manifest) error {
	u, err := url.Parse(hubURL)
	if err != nil {
		return fmt.Errorf("create request: parse hub url: %w", err)
	}
	if token != "" {
		host := u.Hostname()
		if u.Scheme == "http" && host != "127.0.0.1" && host != "localhost" && host != "::1" {
			return fmt.Errorf("refusing to send SKRET_HUB_TOKEN over insecure http to %q; use https", host)
		}
	}
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	reqURL := u.JoinPath("api/manifest").String()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hub returned %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// --- hub init ---

func (o *hubOptions) runInit(cmd *cobra.Command) error {
	cfgPath, err := resolveConfigFile(o.global)
	if err != nil {
		return skret.WithRemediation(
			skret.NewError(skret.ExitConfigError, "hub init: no config file found", err),
			"run `skret init` first, then `skret hub init` again")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return skret.NewError(skret.ExitConfigError, "hub init: load config failed", err)
	}
	existing, err := os.ReadFile(cfgPath)
	if err != nil {
		return skret.NewError(skret.ExitConfigError, "hub init: read config failed", err)
	}

	// Namespace default: the resolved environment path, exactly what
	// `hub push` would use without sync.hub.namespace. Resolution needs only
	// config (no provider build / no credentials), matching bootstrap.
	ns := o.namespace
	if ns == "" {
		resolved, rerr := resolveBootstrapConfig(o.global)
		if rerr != nil || resolved == nil || resolved.Path == "" {
			return skret.WithRemediation(
				skret.NewError(skret.ExitConfigError,
					"hub init: could not resolve a default namespace from the environment path", rerr),
				"pass --namespace explicitly, e.g. `skret hub init --namespace /myapp/prod`")
		}
		ns = resolved.Path
	}

	cfg.Sync = ensureSyncConfig(cfg.Sync)
	cfg.Sync.Hub = &config.HubConfig{URL: o.url, Namespace: ns}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return skret.NewError(skret.ExitGenericError, "hub init: marshal config", err)
	}
	if bytes.Equal(existing, data) {
		cmd.PrintErrf("hub config unchanged in %s\n", cfgPath)
		return nil
	}
	if err := writeConfigAtomically(cfgPath, data, existing, true); err != nil {
		return skret.NewError(skret.ExitGenericError, "hub init: write config failed", err)
	}
	cmd.PrintErrf("Wrote hub config to %s (url: %s, namespace: %s)\n", cfgPath, o.url, ns)
	return nil
}

// ensureSyncConfig allocates the sync block when the config never declared
// one, so `hub init` on a sync-less .skret.yaml writes a well-formed
// `sync:` mapping instead of a null-valued key.
func ensureSyncConfig(sc *config.SyncConfig) *config.SyncConfig {
	if sc != nil {
		return sc
	}
	return &config.SyncConfig{}
}

// --- hub status ---

// hubNamespaceStat is one row of the status output (both formats).
type hubNamespaceStat struct {
	Namespace   string `json:"namespace"`
	Env         string `json:"env"`
	KeyCount    int    `json:"key_count"`
	GeneratedAt string `json:"generated_at"`
}

// hubStatus is the --format json shape of `hub status`: reachability plus
// the per-namespace stats the worker's /api/status reports. Names-only by
// construction: the worker never sends key names or fingerprints here.
type hubStatus struct {
	OK             bool               `json:"ok"`
	URL            string             `json:"url"`
	NamespaceCount int                `json:"namespace_count"`
	KeyCount       int                `json:"key_count"`
	Namespaces     []hubNamespaceStat `json:"namespaces"`
}

func (o *hubOptions) runStatus(cmd *cobra.Command) error {
	sc, err := loadSyncConfig(o.global)
	if err != nil {
		return skret.NewError(skret.ExitConfigError, "hub status: load config failed", err)
	}
	hubURL, err := resolveHubURL(o.hubURL, sc)
	if err != nil {
		return skret.NewError(skret.ExitConfigError, "hub status: "+err.Error(), nil)
	}

	st, err := fetchHubStatus(hubURL, os.Getenv("SKRET_HUB_TOKEN"))
	if err != nil {
		// fetchHubStatus pre-codes its failures (auth vs network vs config);
		// re-wrapping with that same code keeps `skret hub status`'s exit
		// status truthful instead of flattening 401 into a network error.
		return skret.NewError(skret.ExitCode(err), "hub status: "+err.Error(), nil)
	}
	st.URL = hubURL

	format := bootstrapOutputFormat(cmd)
	if format == "json" {
		data, merr := json.MarshalIndent(st, "", "  ")
		if merr != nil {
			return skret.NewError(skret.ExitGenericError, "hub status: encode result", merr)
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return nil
	}

	stdout := cmd.OutOrStdout()
	fmt.Fprintf(stdout, "URL\t%s\n", hubURL)
	fmt.Fprintf(stdout, "STATUS\t%s\n", map[bool]string{true: "ok", false: "error"}[st.OK])
	fmt.Fprintf(stdout, "KEY COUNT\t%d\n", st.KeyCount)
	if len(st.Namespaces) > 0 {
		w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAMESPACE\tENV\tKEYS\tUPDATED")
		for _, ns := range st.Namespaces {
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", ns.Namespace, ns.Env, ns.KeyCount, ns.GeneratedAt)
		}
		w.Flush()
	}
	return nil
}

// fetchHubStatus GETs the worker's /api/status (same bearer credential as
// push). Every failure is returned pre-coded -- ExitAuthError for 401/403
// (with the fix attached), ExitNetworkError for everything else -- so the
// caller can preserve the code instead of flattening an auth failure into a
// generic network one.
func fetchHubStatus(hubURL, token string) (*hubStatus, error) {
	u, err := url.Parse(hubURL)
	if err != nil {
		return nil, skret.NewError(skret.ExitConfigError, "parse hub url", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u.JoinPath("api/status").String(), http.NoBody)
	if err != nil {
		return nil, skret.NewError(skret.ExitNetworkError, "create request", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, skret.NewError(skret.ExitNetworkError, "get", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, skret.WithRemediation(
			skret.NewError(skret.ExitAuthError,
				fmt.Sprintf("hub returned %d (missing or wrong SKRET_HUB_TOKEN)", resp.StatusCode), nil),
			"export SKRET_HUB_TOKEN=<token> and retry")
	case resp.StatusCode != http.StatusOK:
		b, _ := io.ReadAll(resp.Body)
		return nil, skret.NewError(skret.ExitNetworkError,
			fmt.Sprintf("hub returned %d: %s", resp.StatusCode, string(b)), nil)
	}
	var st hubStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, skret.NewError(skret.ExitNetworkError, "decode status response", err)
	}
	if st.Namespaces == nil {
		st.Namespaces = []hubNamespaceStat{}
	}
	return &st, nil
}
