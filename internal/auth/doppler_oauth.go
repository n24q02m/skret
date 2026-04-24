package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DopplerOAuthFlow implements Doppler's OAuth device-authorization flow.
type DopplerOAuthFlow struct {
	BaseURL      string
	PollInterval time.Duration
	client       *http.Client
}

// NewDopplerOAuthFlow creates a device flow pointing at baseURL (defaults to
// https://api.doppler.com when empty).
func NewDopplerOAuthFlow(baseURL string) *DopplerOAuthFlow {
	if baseURL == "" {
		baseURL = "https://api.doppler.com"
	}
	return &DopplerOAuthFlow{
		BaseURL:      baseURL,
		PollInterval: 5 * time.Second,
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

// Login POSTs /v3/auth/device, opens the approval URL, and polls
// /v3/auth/device/token until approval, error, or deadline.
func (f *DopplerOAuthFlow) Login(ctx context.Context, _ map[string]string) (*Credential, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.BaseURL+"/v3/auth/device", nil)
	if err != nil {
		return nil, fmt.Errorf("doppler oauth: build device request: %w", err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doppler oauth: device request: %w", err)
	}
	var dev struct {
		Code            string `json:"code"`
		AuthURL         string `json:"auth_url"`
		PollingInterval int    `json:"polling_interval"`
		ExpiresIn       int    `json:"expires_in"`
	}
	decodeErr := json.NewDecoder(resp.Body).Decode(&dev)
	_ = resp.Body.Close()
	if decodeErr != nil {
		return nil, fmt.Errorf("doppler oauth: decode device: %w", decodeErr)
	}
	if dev.Code == "" {
		return nil, fmt.Errorf("doppler oauth: empty device code")
	}

	fmt.Fprintf(ctxOut(ctx), "Open %s in your browser to approve skret.\n", dev.AuthURL)
	_ = OpenBrowser(ctx, dev.AuthURL)

	interval := f.PollInterval
	if dev.PollingInterval > 0 && interval >= 5*time.Second {
		interval = time.Duration(dev.PollingInterval) * time.Second
	}
	deadline := time.Now().Add(time.Duration(dev.ExpiresIn) * time.Second)

	form := url.Values{"code": []string{dev.Code}}
	for time.Now().Before(deadline) {
		tReq, err := http.NewRequestWithContext(ctx, http.MethodPost, f.BaseURL+"/v3/auth/device/token", strings.NewReader(form.Encode()))
		if err != nil {
			return nil, fmt.Errorf("doppler oauth: build poll request: %w", err)
		}
		tReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		tResp, err := f.client.Do(tReq)
		if err != nil {
			return nil, fmt.Errorf("doppler oauth: poll: %w", err)
		}
		if tResp.StatusCode == http.StatusAccepted {
			_ = tResp.Body.Close()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(interval):
			}
			continue
		}
		if tResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(tResp.Body)
			_ = tResp.Body.Close()
			return nil, fmt.Errorf("doppler oauth: poll status %d: %s", tResp.StatusCode, string(body))
		}
		var tok struct {
			Token string `json:"token"`
			Name  string `json:"name"`
		}
		err = json.NewDecoder(tResp.Body).Decode(&tok)
		_ = tResp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("doppler oauth: decode token: %w", err)
		}
		return &Credential{
			Method: "oauth",
			Token:  tok.Token,
			Metadata: map[string]string{
				"email": tok.Name,
			},
		}, nil
	}
	return nil, fmt.Errorf("doppler oauth: expired waiting for approval")
}
