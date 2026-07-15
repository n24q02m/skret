package syncer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/n24q02m/skret/internal/provider"
)

var randReader io.Reader = rand.Reader

// GitHubSyncer pushes secrets to GitHub Actions repository secrets.
type GitHubSyncer struct {
	owner      string
	repo       string
	token      string
	baseURL    string
	httpClient *http.Client
}

// NewGitHub creates a GitHub Actions secrets syncer.
func NewGitHub(owner, repo, token, baseURL string) Syncer {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &GitHubSyncer{
		owner:   owner,
		repo:    repo,
		token:   token,
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (g *GitHubSyncer) Name() string { return "github" }

func (g *GitHubSyncer) Sync(ctx context.Context, secrets []*provider.Secret) error {
	if len(secrets) == 0 {
		return nil
	}

	// Deduplicate incoming secrets by key (last value wins).
	dedup := make(map[string]*provider.Secret)
	for _, s := range secrets {
		dedup[s.Key] = s
	}

	uniqueSecrets := make([]*provider.Secret, 0, len(dedup))
	for _, s := range dedup {
		uniqueSecrets = append(uniqueSecrets, s)
	}

	pubKeyB64, keyID, err := g.getPublicKey(ctx)
	if err != nil {
		return err
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if len(pubKeyBytes) != 32 {
		return fmt.Errorf("invalid public key length: %d (expected 32)", len(pubKeyBytes))
	}
	var recipientKey [32]byte
	copy(recipientKey[:], pubKeyBytes)

	const maxConcurrency = 10
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	errCh := make(chan error, len(uniqueSecrets))

	for _, s := range uniqueSecrets {
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

			name := SecretName(s.Key)
			if err := g.putSecret(ctx, name, s.Value, &recipientKey, keyID); err != nil {
				errCh <- fmt.Errorf("github: set %q: %w", name, err)
			}
		}(s)
	}

	wg.Wait()
	close(errCh)

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func (g *GitHubSyncer) getPublicKey(ctx context.Context) (string, string, error) {
	u, err := url.Parse(g.baseURL)
	if err != nil {
		return "", "", fmt.Errorf("github: parse base url: %w", err)
	}
	u = u.JoinPath("repos", g.owner, g.repo, "actions", "secrets", "public-key")
	reqURL := u.String()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, http.NoBody)
	if err != nil {
		return "", "", fmt.Errorf("github: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("github: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", "", fmt.Errorf("github: API returned %d (body unreadable: %w)", resp.StatusCode, readErr)
		}
		return "", "", fmt.Errorf("github: API returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		KeyID string `json:"key_id"`
		Key   string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("github: decode key: %w", err)
	}
	return result.Key, result.KeyID, nil
}

func (g *GitHubSyncer) putSecret(ctx context.Context, name, value string, recipientKey *[32]byte, keyID string) error {
	encValue, err := sealSecret(value, recipientKey)
	if err != nil {
		return fmt.Errorf("github: encrypt %q: %w", name, err)
	}

	u, err := url.Parse(g.baseURL)
	if err != nil {
		return fmt.Errorf("github: parse base url: %w", err)
	}
	u = u.JoinPath("repos", g.owner, g.repo, "actions", "secrets", name)
	reqURL := u.String()

	body := fmt.Sprintf(`{"encrypted_value":%q,"key_id":%q}`, encValue, keyID)
	req, err := http.NewRequestWithContext(ctx, "PUT", reqURL, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("github: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("github: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		respBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("github: API returned %d (body unreadable: %w)", resp.StatusCode, readErr)
		}
		return fmt.Errorf("github: API returned %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// SecretName is the name a sync target stores a secret under: the last
// path segment of the provider key, verbatim. Exported so the CLI can show
// the exact names a sync would write.
func SecretName(key string) string {
	name := key
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	return name
}

// ExistingKeys returns the names of the Actions secrets already present on
// the repository (names only -- values are write-only), paginated at 100.
func (g *GitHubSyncer) ExistingKeys(ctx context.Context) ([]string, error) {
	var names []string
	for page := 1; ; page++ {
		u, err := url.Parse(g.baseURL)
		if err != nil {
			return nil, fmt.Errorf("github: parse base url: %w", err)
		}
		u = u.JoinPath("repos", g.owner, g.repo, "actions", "secrets")
		q := u.Query()
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("github: create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+g.token)
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := g.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("github: list secrets: %w", err)
		}
		var body struct {
			TotalCount int `json:"total_count"`
			Secrets    []struct {
				Name string `json:"name"`
			} `json:"secrets"`
		}
		decodeErr := json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("github: list secrets: status %d", resp.StatusCode)
		}
		if decodeErr != nil {
			return nil, fmt.Errorf("github: decode secrets list: %w", decodeErr)
		}
		for _, s := range body.Secrets {
			names = append(names, s.Name)
		}
		if page*100 >= body.TotalCount {
			return names, nil
		}
	}
}

// sealSecret encrypts a secret using NaCl sealed box (curve25519 + xsalsa20-poly1305).
// This matches GitHub's required encryption format for Actions secrets.
func sealSecret(secret string, recipientKey *[32]byte) (string, error) {
	sealed, err := box.SealAnonymous(nil, []byte(secret), recipientKey, randReader)
	if err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sealed), nil
}

func init() { Register("github", newGitHubFromConfig) }

func newGitHubFromConfig(tc TargetConfig) (Syncer, error) {
	repo := field(tc, "repo")
	if repo == "" {
		return nil, fmt.Errorf("github: repo is required")
	}
	owner, repoName, found := strings.Cut(repo, "/")
	if !found || owner == "" || repoName == "" {
		return nil, fmt.Errorf("github: invalid repo %q, must be owner/repo", repo)
	}
	if tc.Token == "" {
		return nil, fmt.Errorf("github: GITHUB_TOKEN is required")
	}
	return NewGitHub(owner, repoName, tc.Token, field(tc, "base_url")), nil
}
