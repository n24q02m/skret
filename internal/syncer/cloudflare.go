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
			if err := c.putWorkerSecret(ctx, secretName(s.Key), s.Value); err != nil {
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
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("cloudflare: set %q: API returned %d: %s", name, resp.StatusCode, string(b))
	}
	return nil
}

// syncPages is a stub for Task 4.
func (c *CloudflareSyncer) syncPages(ctx context.Context, secrets []*provider.Secret) error {
	return fmt.Errorf("cloudflare: pages mode not yet implemented")
}

// ListNames returns the list of secret names currently set on the Worker.
func (c *CloudflareSyncer) ListNames(ctx context.Context) ([]string, error) {
	// TODO: Implement ListNames for Cloudflare
	return nil, fmt.Errorf("cloudflare: ListNames not yet implemented")
}
