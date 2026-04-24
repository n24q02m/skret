package auth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInfisicalBrowserFlow_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" {
			var body struct {
				Code         string `json:"code"`
				CodeVerifier string `json:"code_verifier"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			assert.NotEmpty(t, body.Code)
			assert.NotEmpty(t, body.CodeVerifier)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "inf.access.test",
				"email":        "user@example.com",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	flow := auth.NewInfisicalBrowserFlow(srv.URL)
	// Simulate the browser: parse the callback URL embedded in authURL and
	// hit it directly with a code query param (the upstream Infisical server
	// would normally 302-redirect the user's browser to this callback).
	flow.Opener = func(bgctx context.Context, authURL string) error {
		go func() {
			time.Sleep(100 * time.Millisecond)
			u, perr := url.Parse(authURL)
			if perr != nil {
				return
			}
			cb := u.Query().Get("callback")
			if cb == "" {
				return
			}
			req, _ := http.NewRequestWithContext(bgctx, http.MethodGet, cb+"?code=browser-code", http.NoBody)
			resp, _ := http.DefaultClient.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cred, err := flow.Login(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, "browser", cred.Method)
	assert.Equal(t, "inf.access.test", cred.Token)
	assert.Equal(t, "user@example.com", cred.Metadata["email"])
}

func TestInfisicalBrowserFlow_ContextCancel(t *testing.T) {
	flow := auth.NewInfisicalBrowserFlow("https://example.invalid")
	flow.Opener = func(_ context.Context, _ string) error { return fmt.Errorf("no browser") }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := flow.Login(ctx, nil)
	require.Error(t, err)
}
