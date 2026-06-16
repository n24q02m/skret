package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

type dopplerOAuthFlow interface {
	Login(ctx context.Context, opts map[string]string) (*Credential, error)
}

// dopplerProvider implements auth.Provider for Doppler.
type dopplerProvider struct {
	baseURL string
	oauth   dopplerOAuthFlow
}

// NewDopplerProvider creates the Doppler auth provider.
func NewDopplerProvider() Provider {
	baseURL := "https://api.doppler.com"
	return &dopplerProvider{
		baseURL: baseURL,
		oauth:   NewDopplerOAuthFlow(baseURL),
	}
}

func (p *dopplerProvider) Name() string { return "doppler" }

func (p *dopplerProvider) Methods() []Method {
	return []Method{
		{Name: "oauth", Description: "Doppler OAuth device flow (recommended)", Interactive: true},
		{Name: "service-token", Description: "Paste a Doppler service token", Interactive: true},
		{Name: "personal-token", Description: "Paste a Doppler personal token", Interactive: true},
	}
}

func (p *dopplerProvider) Login(ctx context.Context, method string, opts map[string]string) (*Credential, error) {
	switch method {
	case "oauth":
		return p.oauth.Login(ctx, opts)
	case "service-token", "personal-token":
		return p.loginToken(ctx, method, opts)
	default:
		return nil, fmt.Errorf("doppler: %w: %s", ErrAuthMethodUnsupported, method)
	}
}

func (p *dopplerProvider) loginToken(ctx context.Context, method string, opts map[string]string) (*Credential, error) {
	token := opts["token"]
	if token == "" {
		token = os.Getenv("DOPPLER_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("doppler: token required (set via --opt token=... or DOPPLER_TOKEN env)")
	}

	// Validate token against /v3/me
	client := &http.Client{Timeout: 10 * time.Second}

	base, err := url.Parse(p.baseURL)
	if err != nil {
		return nil, fmt.Errorf("doppler: invalid base url: %w", err)
	}
	reqURL := base.JoinPath("v3/me").String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("doppler: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doppler: validate token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("doppler: token validation failed (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Workplace struct {
			Name string `json:"name"`
		} `json:"workplace"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	return &Credential{
		Method: method,
		Token:  token,
		Metadata: map[string]string{
			"workplace": result.Workplace.Name,
		},
	}, nil
}

func (p *dopplerProvider) Validate(_ context.Context, cred *Credential) error {
	if cred == nil || cred.Token == "" {
		return fmt.Errorf("doppler: invalid credential")
	}
	return nil
}

func (p *dopplerProvider) Logout(_ context.Context) error {
	return nil
}

func init() {
	Register("doppler", NewDopplerProvider())
}
