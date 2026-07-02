package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
	cmd := &cobra.Command{Use: "hub", Short: "Publish secret inventory to the vault dashboard"}
	push := &cobra.Command{
		Use:   "push",
		Short: "Push a names-only manifest (no values) to the hub",
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

	sc, err := loadSyncConfig()
	if err != nil {
		return skret.NewError(skret.ExitConfigError, "hub push: load config failed", err)
	}

	hubURL := o.hubURL
	if hubURL == "" && sc != nil && sc.Hub != nil {
		hubURL = sc.Hub.URL
	}
	if hubURL == "" {
		return skret.NewError(skret.ExitConfigError, "hub push: no hub URL (set --hub-url or sync.hub.url in .skret.yaml)", nil)
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

	states := loadHubStates(sc)
	m := syncer.BuildManifest(resolved.Path, resolved.EnvName, salt, secrets, states)
	m.GeneratedAt = time.Now().UTC()

	token := os.Getenv("SKRET_HUB_TOKEN")
	if err := postManifest(hubURL, token, m); err != nil {
		return skret.NewError(skret.ExitNetworkError, "hub push: post manifest failed", err)
	}
	cmd.PrintErrf("Pushed manifest: %d keys to %s\n", len(m.Keys), hubURL)
	return nil
}

// loadHubStates loads each declared sync target's last-synced state, keyed
// as "<type>:<stateID>" to match syncer.BuildManifest's ManifestKey.Targets
// naming. A target with no prior sync (LoadSyncState returns an empty state
// on first run, never an error) still contributes an entry — BuildManifest
// then marks every key "missing" for it, which is the correct drift signal.
func loadHubStates(sc *config.SyncConfig) map[string]*syncer.SyncState {
	states := map[string]*syncer.SyncState{}
	if sc == nil {
		return states
	}
	for _, t := range sc.Targets {
		tc := targetFromConfig(t) // Task 5 helper: resolves Fields/Token from env
		id := targetStateID(hubSyncerStub(t.Type), tc)
		st, err := syncer.LoadSyncState(t.Type, id)
		if err != nil {
			continue // corrupt/unreadable state file -> target absent from manifest
		}
		states[t.Type+":"+id] = st
	}
	return states
}

// hubSyncerStub returns a syncer.Syncer of the requested type purely to
// resolve its Name() for the Task 5 targetStateID helper. hub push only
// reads cached sync-state files — it never calls Sync() — so the
// constructor arguments (repo/worker/token/...) are irrelevant and left
// empty.
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
// fingerprints, and per-target drift status.
func postManifest(hubURL, token string, m *syncer.Manifest) error {
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, hubURL+"/api/manifest", bytes.NewReader(body))
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
