package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DopplerProvider implements auth.Provider for Doppler.
type DopplerProvider struct {
	baseURL string
}

// NewDopplerProvider creates the Doppler auth provider.
func NewDopplerProvider() *DopplerProvider {
	return &DopplerProvider{baseURL: "https://api.doppler.com"}
}

func (p *DopplerProvider) Name() string { return "doppler" }

func (p *DopplerProvider) Methods() []Method {
	return []Method{
		{Name: "service-token", Description: "Paste a Doppler service token", Interactive: true},
		{Name: "personal-token", Description: "Paste a Doppler personal token", Interactive: true},
	}
}

func (p *DopplerProvider) Login(_ context.Context, method string, opts map[string]string) (*Credential, error) {
	switch method {
	case "service-token", "personal-token":
		return p.loginToken(method, opts)
	default:
		return nil, fmt.Errorf("doppler: %w: %s", ErrAuthMethodUnsupported, method)
	}
}

func (p *DopplerProvider) loginToken(method string, opts map[string]string) (*Credential, error) {
	token := opts["token"]
	if token == "" {
		return nil, fmt.Errorf("doppler: token required (set via --token or DOPPLER_TOKEN)")
	}

	// Validate token against /v3/me
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", p.baseURL+"/v3/me", http.NoBody)
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

func (p *DopplerProvider) Validate(_ context.Context, cred *Credential) error {
	if cred == nil || cred.Token == "" {
		return fmt.Errorf("doppler: invalid credential")
	}
	return nil
}

func (p *DopplerProvider) Logout(_ context.Context) error {
	return nil
}

func init() {
	Register("doppler", NewDopplerProvider())
}
