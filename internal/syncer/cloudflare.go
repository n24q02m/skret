package syncer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/n24q02m/skret/internal/provider"
)

// CloudflareSyncer pushes secrets to a CF Worker script (Secrets) or a CF
// Pages project (production env_vars). Exactly one of worker/pages is set.
type CloudflareSyncer struct {
	accountID  string
	worker     string
	pages      string
	token      string
	baseURL    string
	httpClient *http.Client
}

// NewCloudflare builds a Cloudflare syncer. baseURL defaults to the public API.
func NewCloudflare(accountID, worker, pages, token, baseURL string) Syncer {
	if baseURL == "" {
		baseURL = "https://api.cloudflare.com/client/v4"
	}
	return &CloudflareSyncer{
		accountID: accountID, worker: worker, pages: pages, token: token, baseURL: baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *CloudflareSyncer) Name() string {
	return "cloudflare"
}

func (c *CloudflareSyncer) Sync(ctx context.Context, secrets []*provider.Secret) error {
	if len(secrets) == 0 {
		return nil
	}
	if c.pages != "" {
		return c.syncPages(ctx, secrets) // Task 4
	}
	return c.syncWorker(ctx, secrets)
}

func (c *CloudflareSyncer) syncWorker(ctx context.Context, secrets []*provider.Secret) error {
	const maxConcurrency = 10
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	errCh := make(chan error, len(secrets))
	for _, s := range secrets {
		wg.Add(1)
		go func(s *provider.Secret) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			}
			if err := c.putWorkerSecret(ctx, SecretName(s.Key), s.Value); err != nil {
				errCh <- err
			}
		}(s)
	}
	wg.Wait()
	close(errCh)
	if err := <-errCh; err != nil {
		return err
	}
	return nil
}

func (c *CloudflareSyncer) putWorkerSecret(ctx context.Context, name, value string) error {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("cloudflare: parse base url: %w", err)
	}
	u = u.JoinPath("accounts", c.accountID, "workers", "scripts", c.worker, "secrets")
	body, err := json.Marshal(map[string]string{"name": name, "text": value, "type": "secret_text"})
	if err != nil {
		return fmt.Errorf("cloudflare: marshal %q: %w", name, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("cloudflare: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: set %q: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("cloudflare: set %q: API returned %d (body unreadable: %w)", name, resp.StatusCode, readErr)
		}
		return fmt.Errorf("cloudflare: set %q: API returned %d: %s", name, resp.StatusCode, string(b))
	}
	return nil
}

func (c *CloudflareSyncer) syncPages(ctx context.Context, secrets []*provider.Secret) error {
	// CF Pages PATCH is a partial-merge (JSON Merge Patch): only the keys we
	// send are updated; keys we omit are preserved server-side. So we send
	// ONLY the keys being synced. We must NOT GET-merge-PATCH: secret_text
	// values are masked ("") on GET, so reading them back and re-PATCHing
	// would blank every pre-existing secret. (Verified live 2026-07-02.)
	env := make(map[string]map[string]string, len(secrets))
	for _, s := range secrets {
		env[SecretName(s.Key)] = map[string]string{"type": "secret_text", "value": s.Value}
	}
	payload := map[string]any{
		"deployment_configs": map[string]any{
			"production": map[string]any{"env_vars": env},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("cloudflare: marshal pages env: %w", err)
	}
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("cloudflare: parse base url: %w", err)
	}
	u = u.JoinPath("accounts", c.accountID, "pages", "projects", c.pages)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u.String(), strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("cloudflare: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: patch pages: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("cloudflare: patch pages: API returned %d (body unreadable: %w)", resp.StatusCode, readErr)
		}
		return fmt.Errorf("cloudflare: patch pages: API returned %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// ExistingKeys returns the names of the secrets already set on the worker
// script. Pages targets cannot enumerate env vars equivalently, so
// no-overwrite is rejected for them.
func (c *CloudflareSyncer) ExistingKeys(ctx context.Context) ([]string, error) {
	if c.pages != "" {
		return nil, fmt.Errorf("cloudflare: pages targets cannot enumerate existing secret names")
	}
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: parse base url: %w", err)
	}
	u = u.JoinPath("accounts", c.accountID, "workers", "scripts", c.worker, "secrets")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: list worker secrets: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudflare: list worker secrets: status %d", resp.StatusCode)
	}
	var body struct {
		Result []struct {
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("cloudflare: decode worker secrets: %w", err)
	}
	names := make([]string, 0, len(body.Result))
	for _, s := range body.Result {
		names = append(names, s.Name)
	}
	return names, nil
}

func init() { Register("cloudflare", newCloudflareFromConfig) }

func newCloudflareFromConfig(tc TargetConfig) (Syncer, error) {
	worker, pages := field(tc, "worker"), field(tc, "pages")
	if worker == "" && pages == "" {
		return nil, fmt.Errorf("cloudflare: worker or pages is required")
	}
	account := field(tc, "account")
	if account == "" {
		return nil, fmt.Errorf("cloudflare: account is required")
	}
	if tc.Token == "" {
		return nil, fmt.Errorf("cloudflare: CLOUDFLARE_API_TOKEN is required")
	}
	return NewCloudflare(account, worker, pages, tc.Token, field(tc, "base_url")), nil
}
