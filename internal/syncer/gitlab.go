package syncer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/n24q02m/skret/internal/provider"
)

// GitLabSyncer upserts secrets as project CI/CD variables through the GitLab
// project variables API. Each secret becomes one variable keyed by its
// target-side SecretName; masked and protected mirror the target config.
type GitLabSyncer struct {
	projectID  string // numeric id or group/project path (sent URL-escaped)
	token      string
	baseURL    string
	masked     bool
	protected  bool
	httpClient *http.Client
}

var _ PerKeySyncer = (*GitLabSyncer)(nil)

// NewGitLab creates a GitLab CI/CD variables syncer. baseURL defaults to the
// public GitLab API origin.
func NewGitLab(projectID, token, baseURL string, masked, protected bool) *GitLabSyncer {
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}
	return &GitLabSyncer{
		projectID:  projectID,
		token:      token,
		baseURL:    baseURL,
		masked:     masked,
		protected:  protected,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (g *GitLabSyncer) Name() string { return "gitlab" }

// validGitLabVariableKey enforces GitLab's own key rule: at most 255
// characters drawn from A-Z, a-z, 0-9 and _.
func validGitLabVariableKey(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_':
		default:
			return false
		}
	}
	return true
}

// SyncKey upserts exactly one project variable. The provider mutation is a
// single attempt per request; ambiguous responses are returned for
// reconciliation rather than replayed, so a transient PUT failure never falls
// through to a create.
func (g *GitLabSyncer) SyncKey(ctx context.Context, secret *provider.Secret) error {
	if secret == nil {
		return fmt.Errorf("gitlab: secret is nil")
	}
	name := SecretName(secret.Key)
	if !validGitLabVariableKey(name) {
		return fmt.Errorf("gitlab: key %q is not a valid GitLab CI/CD variable name (only A-Z, a-z, 0-9 and _ are allowed, at most 255 characters); rename the provider key so its last segment is valid", name)
	}

	err := g.putVariable(ctx, name, secret.Value)
	if err == nil {
		return nil
	}
	// A variable that does not exist yet is reported as 404 (current GitLab)
	// or 400 "variable is not found" (older releases). Both are safe to
	// follow with a create: the PUT cannot have applied. Transient or
	// ambiguous PUT failures are NOT retried here.
	var status *HTTPStatusError
	if errors.As(err, &status) {
		switch status.StatusCode {
		case http.StatusNotFound, http.StatusBadRequest:
			return g.createVariable(ctx, name, secret.Value)
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf("gitlab: update %q: %w; check that GITLAB_TOKEN is valid and has the api scope on this project", name, err)
		}
	}
	return err
}

// Sync upserts every secret, one variable per key, stopping at the first
// failure so partial writes stay visible in the operation journal.
func (g *GitLabSyncer) Sync(ctx context.Context, secrets []*provider.Secret) error {
	if len(secrets) == 0 {
		return nil
	}
	if err := ValidateDestinationMapping(g.Name(), secrets); err != nil {
		return err
	}
	for _, s := range secrets {
		if err := g.SyncKey(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

func (g *GitLabSyncer) variablesURL(parts ...string) (*url.URL, error) {
	u, err := url.Parse(g.baseURL)
	if err != nil {
		return nil, fmt.Errorf("gitlab: parse base url: %w", err)
	}
	segments := append([]string{"api", "v4", "projects", url.PathEscape(g.projectID)}, parts...)
	u = u.JoinPath(segments...)
	return u, nil
}

func (g *GitLabSyncer) putVariable(ctx context.Context, name, value string) error {
	u, err := g.variablesURL("variables", url.PathEscape(name))
	if err != nil {
		return err
	}
	return g.mutateVariable(ctx, http.MethodPut, u, name, value, http.StatusOK, "update")
}

func (g *GitLabSyncer) createVariable(ctx context.Context, name, value string) error {
	u, err := g.variablesURL("variables")
	if err != nil {
		return err
	}
	err = g.mutateVariable(ctx, http.MethodPost, u, name, value, http.StatusCreated, "create")
	if err == nil {
		return nil
	}
	var status *HTTPStatusError
	if errors.As(err, &status) && status.StatusCode == http.StatusBadRequest {
		return fmt.Errorf("gitlab: create %q: %w; if masked is enabled the value must satisfy GitLab masking requirements (single line, at least 8 characters, limited charset) -- sync with masked: false or change the value", name, err)
	}
	return err
}

func (g *GitLabSyncer) mutateVariable(
	ctx context.Context,
	method string,
	u *url.URL,
	name, value string,
	success int,
	action string,
) error {
	// Values ride in a JSON body, never in a URL. The response body is never
	// retained in errors -- GitLab can echo values in masking errors.
	body, err := json.Marshal(map[string]any{
		"key":       name,
		"value":     value,
		"masked":    g.masked,
		"protected": g.protected,
	})
	if err != nil {
		return fmt.Errorf("gitlab: marshal variable %q: %w", name, err)
	}
	resp, err := doMutation(ctx, g.httpClient, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(string(body)))
		if err != nil {
			return nil, fmt.Errorf("gitlab: create request: %w", err)
		}
		req.Header.Set("PRIVATE-TOKEN", g.token)
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}, success)
	if err != nil {
		return fmt.Errorf("gitlab: %s %q: %w", action, name, err)
	}
	defer resp.Body.Close()
	return nil
}

// ExistingKeys returns the names of the project variables already present
// (names only -- values are write-only), paginated at 100.
func (g *GitLabSyncer) ExistingKeys(ctx context.Context) ([]string, error) {
	var names []string
	for page := 1; ; page++ {
		u, err := g.variablesURL("variables")
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		u.RawQuery = q.Encode()

		resp, err := doWithRetry(ctx, g.httpClient, func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
			if err != nil {
				return nil, fmt.Errorf("gitlab: create request: %w", err)
			}
			req.Header.Set("PRIVATE-TOKEN", g.token)
			return req, nil
		}, http.StatusOK)
		if err != nil {
			return nil, fmt.Errorf("gitlab: list variables: %w", err)
		}
		var batch []struct {
			Key string `json:"key"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("gitlab: decode variables: %w", err)
		}
		resp.Body.Close()
		for _, v := range batch {
			names = append(names, v.Key)
		}
		if len(batch) < 100 {
			return names, nil
		}
	}
}

func init() { Register("gitlab", newGitLabFromConfig) }

func newGitLabFromConfig(tc TargetConfig) (Syncer, error) {
	project := field(tc, "project")
	if project == "" {
		return nil, fmt.Errorf("gitlab: project is required (project id or group/project path)")
	}
	if tc.Token == "" {
		return nil, fmt.Errorf("gitlab: GITLAB_TOKEN is required")
	}
	return NewGitLab(
		project,
		tc.Token,
		field(tc, "base_url"),
		field(tc, "masked") == "true",
		field(tc, "protected") == "true",
	), nil
}
