package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// InfisicalBrowserFlow implements an Infisical PKCE browser login using a
// loopback HTTP listener as the redirect target.
type InfisicalBrowserFlow struct {
	BaseURL string
	Opener  func(ctx context.Context, authURL string) error
	client  *http.Client
}

// NewInfisicalBrowserFlow creates a browser flow pointing at baseURL (defaults
// to https://app.infisical.com when empty). The Opener hook is overridable for
// tests.
func NewInfisicalBrowserFlow(baseURL string) *InfisicalBrowserFlow {
	if baseURL == "" {
		baseURL = "https://app.infisical.com"
	}
	return &InfisicalBrowserFlow{
		BaseURL: baseURL,
		Opener:  OpenBrowser,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// pkcePair generates a 32-byte random verifier and its base64url S256
// challenge per RFC 7636.
func pkcePair() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// Login starts a loopback listener, opens the Infisical auth redirect, waits
// for the browser callback with the code, and exchanges it for an access
// token via /api/v1/auth/token.
func (f *InfisicalBrowserFlow) Login(ctx context.Context, _ map[string]string) (*Credential, error) {
	verifier, challenge, err := pkcePair()
	if err != nil {
		return nil, fmt.Errorf("infisical browser: pkce: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("infisical browser: listen: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			code := r.URL.Query().Get("code")
			if code == "" {
				http.Error(w, "missing code", http.StatusBadRequest)
				errCh <- fmt.Errorf("infisical browser: callback missing code")
				return
			}
			_, _ = w.Write([]byte("skret authentication complete. You can close this tab."))
			codeCh <- code
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	callback := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	authURL := f.BaseURL + "/api/v1/auth/redirect?" + url.Values{
		"callback":       {callback},
		"code_challenge": {challenge},
		"method":         {"S256"},
	}.Encode()
	fmt.Fprintf(ctxOut(ctx), "Open %s in your browser to approve skret.\n", authURL)
	_ = f.Opener(ctx, authURL)

	var code string
	select {
	case code = <-codeCh:
	case err = <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("infisical browser: callback timeout")
	}

	body, err := json.Marshal(map[string]string{"code": code, "code_verifier": verifier})
	if err != nil {
		return nil, fmt.Errorf("infisical browser: marshal body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.BaseURL+"/api/v1/auth/token", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("infisical browser: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("infisical browser: token exchange: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("infisical browser: token status %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		Email       string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("infisical browser: decode token: %w", err)
	}
	return &Credential{
		Method: "browser",
		Token:  out.AccessToken,
		Metadata: map[string]string{
			"email": out.Email,
			"url":   f.BaseURL,
		},
	}, nil
}
