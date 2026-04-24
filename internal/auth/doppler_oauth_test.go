package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDopplerOAuthFlow_Success(t *testing.T) {
	polls := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/auth/device":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":             "dev-code",
				"auth_url":         srv.URL + "/approve",
				"polling_interval": 1,
				"expires_in":       60,
			})
		case "/v3/auth/device/token":
			polls++
			if polls < 2 {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token": "dp.pt.test",
				"name":  "test@example.com",
			})
		}
	}))
	defer srv.Close()

	flow := auth.NewDopplerOAuthFlow(srv.URL)
	flow.PollInterval = 50 * time.Millisecond // speed up test
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cred, err := flow.Login(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, "oauth", cred.Method)
	assert.Equal(t, "dp.pt.test", cred.Token)
	assert.Equal(t, "test@example.com", cred.Metadata["email"])
	assert.GreaterOrEqual(t, polls, 2)
}

func TestDopplerOAuthFlow_ContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3/auth/device" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": "c", "auth_url": "http://x", "polling_interval": 1, "expires_in": 60,
			})
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	flow := auth.NewDopplerOAuthFlow(srv.URL)
	flow.PollInterval = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	_, err := flow.Login(ctx, nil)
	require.Error(t, err)
}
