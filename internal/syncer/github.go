package syncer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/n24q02m/skret/internal/provider"
)

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

	// Deduplicate secrets by key (last value wins)
	dedupMap := make(map[string]*provider.Secret, len(secrets))
	var uniqueKeys []string
	for _, s := range secrets {
		if _, exists := dedupMap[s.Key]; !exists {
			uniqueKeys = append(uniqueKeys, s.Key)
		}
		dedupMap[s.Key] = s
	}

	var uniqueSecrets []*provider.Secret
	for _, k := range uniqueKeys {
		uniqueSecrets = append(uniqueSecrets, dedupMap[k])
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

	var pubKey [32]byte
	copy(pubKey[:], pubKeyBytes)

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

			if err := g.putSecret(ctx, s.Key, s.Value, &pubKey, keyID); err != nil {
				errCh <- fmt.Errorf("github: set %q: %w", s.Key, err)
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
	url := fmt.Sprintf("%s/repos/%s/%s/actions/secrets/public-key", g.baseURL, g.owner, g.repo)

	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
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

func (g *GitHubSyncer) putSecret(ctx context.Context, name, value string, pubKey *[32]byte, keyID string) error {
	encValue, err := sealSecret(value, pubKey)
	if err != nil {
		return fmt.Errorf("github: encrypt %q: %w", name, err)
	}

	url := fmt.Sprintf("%s/repos/%s/%s/actions/secrets/%s", g.baseURL, g.owner, g.repo, name)

	body := fmt.Sprintf(`{"encrypted_value":%q,"key_id":%q}`, encValue, keyID)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, strings.NewReader(body))
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

// sealSecret encrypts a secret using NaCl sealed box (curve25519 + xsalsa20-poly1305).
// This matches GitHub's required encryption format for Actions secrets.
func sealSecret(secret string, recipientKey *[32]byte) (string, error) {
	sealed, err := box.SealAnonymous(nil, []byte(secret), recipientKey, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sealed), nil
}
