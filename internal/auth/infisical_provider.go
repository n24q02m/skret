package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// InfisicalProvider implements auth.Provider for Infisical.
type InfisicalProvider struct {
	baseURL string
}

// NewInfisicalProvider creates the Infisical auth provider.
func NewInfisicalProvider() *InfisicalProvider {
	return &InfisicalProvider{baseURL: "https://app.infisical.com"}
}

func (p *InfisicalProvider) Name() string { return "infisical" }

func (p *InfisicalProvider) Methods() []Method {
	return []Method{
		{Name: "universal-auth", Description: "Machine identity (client-id + client-secret)", Interactive: true},
		{Name: "token", Description: "Paste an Infisical service token", Interactive: true},
	}
}

func (p *InfisicalProvider) Login(_ context.Context, method string, opts map[string]string) (*Credential, error) {
	switch method {
	case "universal-auth":
		return p.loginUniversalAuth(opts)
	case "token":
		return p.loginToken(opts)
	default:
		return nil, fmt.Errorf("infisical: %w: %s", ErrAuthMethodUnsupported, method)
	}
}

func (p *InfisicalProvider) loginUniversalAuth(opts map[string]string) (*Credential, error) {
	clientID := opts["client_id"]
	clientSecret := opts["client_secret"]
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("infisical: client_id and client_secret required")
	}

	return &Credential{
		Method: "universal-auth",
		Token:  clientSecret,
		Metadata: map[string]string{
			"client_id": clientID,
		},
	}, nil
}

func (p *InfisicalProvider) loginToken(opts map[string]string) (*Credential, error) {
	token := opts["token"]
	if token == "" {
		return nil, fmt.Errorf("infisical: token required (set via --token or INFISICAL_TOKEN)")
	}

	// Validate token
	client := &http.Client{Timeout: 10 * time.Second}
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, "GET", p.baseURL+"/api/v1/auth/check", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("infisical: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("infisical: validate token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("infisical: token validation failed (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	return &Credential{
		Method: "token",
		Token:  token,
		Metadata: map[string]string{
			"email": result.User.Email,
		},
	}, nil
}

func (p *InfisicalProvider) Validate(_ context.Context, cred *Credential) error {
	if cred == nil || cred.Token == "" {
		return fmt.Errorf("infisical: invalid credential")
	}
	return nil
}

func (p *InfisicalProvider) Logout(_ context.Context) error {
	return nil
}

func init() {
	Register("infisical", NewInfisicalProvider())
}
