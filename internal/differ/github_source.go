package differ

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type githubSource struct {
	owner, repo, token, baseURL string
	client                      *http.Client
}

// NewGitHubSource builds a presence-only Source over GitHub Actions repo secrets.
// baseURL defaults to https://api.github.com when empty.
func NewGitHubSource(owner, repo, token, baseURL string) Source {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return githubSource{
		owner:   owner,
		repo:    repo,
		token:   token,
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (g githubSource) Label() string { return fmt.Sprintf("github:%s/%s", g.owner, g.repo) }

func (g githubSource) Read(ctx context.Context) (Snapshot, error) {
	out := map[string]string{}
	page := 1
	for {
		names, more, err := g.fetchPage(ctx, page)
		if err != nil {
			return Snapshot{}, fmt.Errorf("read %s: %w", g.Label(), err)
		}
		for _, n := range names {
			out[n] = ""
		}
		if !more {
			break
		}
		page++
	}
	return Snapshot{Secrets: out, CanReadValues: false}, nil
}

func (g githubSource) fetchPage(ctx context.Context, page int) ([]string, bool, error) {
	joinedURL, err := url.JoinPath(g.baseURL, "repos", g.owner, g.repo, "actions", "secrets")
	if err != nil {
		return nil, false, err
	}
	u, err := url.Parse(joinedURL)
	if err != nil {
		return nil, false, err
	}

	q := u.Query()
	q.Set("per_page", "100")
	q.Set("page", strconv.Itoa(page))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "token "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("github API returned status %d", resp.StatusCode)
	}

	var body struct {
		TotalCount int `json:"total_count"`
		Secrets    []struct {
			Name string `json:"name"`
		} `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, false, err
	}
	names := make([]string, 0, len(body.Secrets))
	for _, s := range body.Secrets {
		names = append(names, s.Name)
	}
	more := page*100 < body.TotalCount
	return names, more, nil
}
