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

	"golang.org/x/crypto/nacl/box"

	"github.com/n24q02m/skret/internal/provider"
)

// GitHubSyncer pushes secrets to GitHub Actions repository secrets.
type GitHubSyncer struct {
	owner   string
	repo    string
	token   string
	baseURL string
}

// NewGitHub creates a GitHub Actions secrets syncer.
func NewGitHub(owner, repo, token, baseURL string) Syncer {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &GitHubSyncer{owner: owner, repo: repo, token: token, baseURL: baseURL}
}

func (g *GitHubSyncer) Name() string { return "github" }

func (g *GitHubSyncer) Sync(ctx context.Context, secrets []*provider.Secret) error {
	pubKey, keyID, err := g.getPublicKey(ctx)
	if err != nil {
		return err
	}

	// ⚡ Bolt Optimization: Parallelize N+1 external API calls
	// External APIs like GitHub Secrets often lack batch endpoints.
	// We use a worker pool with a semaphore channel (max 10 concurrent requests)
	// to limit concurrency while dramatically speeding up bulk syncs.
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	errCh := make(chan error, len(secrets))

	for _, s := range secrets {
		wg.Add(1)
		sem <- struct{}{} // acquire

		go func(s *provider.Secret) {
			defer wg.Done()
			defer func() { <-sem }() // release

			if err := g.putSecret(ctx, s.Key, s.Value, pubKey, keyID); err != nil {
				errCh <- fmt.Errorf("github: set %q: %w", s.Key, err)
			}
		}(s)
	}

	wg.Wait()
	close(errCh)

	// Return the first error if any occurred
	for err := range errCh {
		if err != nil {
			return err
		}
	}

	return nil
}

func (g *GitHubSyncer) getPublicKey(ctx context.Context) (string, string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/actions/secrets/public-key", g.baseURL, g.owner, g.repo)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", "", fmt.Errorf("github: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("github: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
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

func (g *GitHubSyncer) putSecret(ctx context.Context, name, value, pubKeyB64, keyID string) error {
	encValue, err := sealSecret(value, pubKeyB64)
	if err != nil {
		return fmt.Errorf("github: encrypt %q: %w", name, err)
	}

	url := fmt.Sprintf("%s/repos/%s/%s/actions/secrets/%s", g.baseURL, g.owner, g.repo, name)

	body := fmt.Sprintf(`{"encrypted_value":"%s","key_id":"%s"}`, encValue, keyID)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("github: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("github: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("github: API returned %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// sealSecret encrypts a secret using NaCl sealed box (curve25519 + xsalsa20-poly1305).
// This matches GitHub's required encryption format for Actions secrets.
func sealSecret(secret, recipientPubKeyB64 string) (string, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(recipientPubKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode public key: %w", err)
	}
	if len(pubKeyBytes) != 32 {
		return "", fmt.Errorf("invalid public key length: %d (expected 32)", len(pubKeyBytes))
	}

	var recipientKey [32]byte
	copy(recipientKey[:], pubKeyBytes)

	sealed, err := box.SealAnonymous(nil, []byte(secret), &recipientKey, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sealed), nil
}
