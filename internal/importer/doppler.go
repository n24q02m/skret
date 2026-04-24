package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

// DopplerImporter reads secrets from the Doppler API.
type DopplerImporter struct {
	token   string
	project string
	config  string
	baseURL string
}

// NewDoppler creates a Doppler API importer.
func NewDoppler(token, project, config, baseURL string) Importer {
	if baseURL == "" {
		baseURL = "https://api.doppler.com"
	}
	return &DopplerImporter{token: token, project: project, config: config, baseURL: baseURL}
}

func (d *DopplerImporter) Name() string { return "doppler" }

func (d *DopplerImporter) Import(ctx context.Context) ([]ImportedSecret, error) {
	url := fmt.Sprintf("%s/v3/configs/config/secrets?project=%s&config=%s", d.baseURL, d.project, d.config)

	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("doppler: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	req.Header.Set("Accept", "application/json")

	// SECURITY: Use a custom HTTP client with an explicit timeout to prevent resource exhaustion and indefinite hangs.
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doppler: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("doppler: API returned %d (body unreadable: %w)", resp.StatusCode, readErr)
		}
		return nil, fmt.Errorf("doppler: API returned %d: %s", resp.StatusCode, string(body))
	}

	var payload struct {
		Secrets map[string]struct {
			Raw      string `json:"raw"`
			Computed string `json:"computed"`
		} `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("doppler: decode response: %w", err)
	}

	secrets := make([]ImportedSecret, 0, len(payload.Secrets))
	for key, val := range payload.Secrets {
		secrets = append(secrets, ImportedSecret{Key: key, Value: val.Raw})
	}
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].Key < secrets[j].Key })
	return secrets, nil
}
