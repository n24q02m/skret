package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
)

// InfisicalImporter reads secrets from the Infisical API.
type InfisicalImporter struct {
	token     string
	projectID string
	env       string
	baseURL   string
}

// NewInfisical creates an Infisical API importer.
func NewInfisical(token, projectID, env, baseURL string) Importer {
	if baseURL == "" {
		baseURL = "https://app.infisical.com"
	}
	return &InfisicalImporter{token: token, projectID: projectID, env: env, baseURL: baseURL}
}

func (i *InfisicalImporter) Name() string { return "infisical" }

func (i *InfisicalImporter) Import(ctx context.Context) ([]ImportedSecret, error) {
	url := fmt.Sprintf("%s/api/v3/secrets/raw?workspaceId=%s&environment=%s", i.baseURL, i.projectID, i.env)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("infisical: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+i.token)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("infisical: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("infisical: API returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Secrets []struct {
			SecretKey   string `json:"secretKey"`
			SecretValue string `json:"secretValue"`
		} `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("infisical: decode response: %w", err)
	}

	secrets := make([]ImportedSecret, 0, len(result.Secrets))
	for _, s := range result.Secrets {
		secrets = append(secrets, ImportedSecret{Key: s.SecretKey, Value: s.SecretValue})
	}
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].Key < secrets[j].Key })
	return secrets, nil
}
