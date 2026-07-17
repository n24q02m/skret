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
	"time"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/syncer"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
)

type hubOptions struct {
	global *GlobalOpts
	hubURL string
}

func newHubCmd(opts *GlobalOpts) *cobra.Command {
	o := &hubOptions{global: opts}
	cmd := &cobra.Command{
		Use:   "hub",
		Short: "Publish secret inventory to the vault dashboard",
		Long: "Groups subcommands that publish secret inventory to the vault dashboard.\n\n" +
			"'hub push' sends a names-only manifest (no values) so the dashboard can show " +
			"presence status (present/absent/unknown) per sync target.",
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
sync.hub.url in .skret.yaml (in that order). A live presence check needs
the same target credentials as 'skret sync' (GITHUB_TOKEN /
CLOUDFLARE_API_TOKEN); the cron sync container already forwards them, a
manual/laptop run must export them itself.`,
		Example: `  skret hub push
  skret hub push --hub-url https://vault.example.com`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.runPush(cmd)
		},
	}
	push.Flags().StringVar(&o.hubURL, "hub-url", "", "hub base URL (overrides sync.hub.url)")
	cmd.AddCommand(push)
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
	hubURL := o.hubURL
	if hubURL == "" {
		hubURL = os.Getenv("SKRET_HUB_URL")
	}
	if hubURL == "" && sc != nil && sc.Hub != nil {
		hubURL = sc.Hub.URL
	}
	if hubURL == "" {
		return skret.NewError(skret.ExitConfigError, "hub push: no hub URL (set --hub-url, SKRET_HUB_URL, or sync.hub.url in .skret.yaml)", nil)
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
	m := syncer.BuildManifest(resolved.Path, resolved.EnvName, salt, secrets, presence)
	m.GeneratedAt = time.Now().UTC()

	token := os.Getenv("SKRET_HUB_TOKEN")
	if err := postManifest(hubURL, token, m); err != nil {
		return skret.NewError(skret.ExitNetworkError, "hub push: post manifest failed", err)
	}
	cmd.PrintErrf("Pushed manifest: %d keys to %s\n", len(m.Keys), hubURL)
	return nil
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
	for _, t := range sc.Targets {
		tc := targetFromConfig(t) // Task 5 helper: resolves Fields/Token from env
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
// clear, so that combination is refused before the request is built. A
// malformed hubURL is not rejected here — it falls through to
// http.NewRequestWithContext below, which reports it as a "create request"
// error the same way it always has.
func postManifest(hubURL, token string, m *syncer.Manifest) error {
	u, err := url.Parse(hubURL)
	if err != nil {
		return fmt.Errorf("invalid hub URL: %w", err)
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
	// Use JoinPath to safely construct the URL and prevent query parameter injection
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, u.JoinPath("api/manifest").String(), bytes.NewReader(body))
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
