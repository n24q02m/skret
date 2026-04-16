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

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("doppler: API returned %d: failed to read body: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("doppler: API returned %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("doppler: decode response: %w", err)
	}

	secrets := make([]ImportedSecret, 0, len(result))
	for key, val := range result {
		secrets = append(secrets, ImportedSecret{Key: key, Value: val["raw"]})
	}
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].Key < secrets[j].Key })
	return secrets, nil
}
