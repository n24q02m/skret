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
	flow.Opener = func(context.Context, string) error { return nil }
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
	flow.Opener = func(context.Context, string) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	_, err := flow.Login(ctx, nil)
	require.Error(t, err)
}

func TestDopplerOAuthFlow_DeviceEndpointError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	flow := auth.NewDopplerOAuthFlow(srv.URL)
	_, err := flow.Login(context.Background(), nil)
	require.Error(t, err)
}

func TestDopplerOAuthFlow_EmptyCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer srv.Close()

	flow := auth.NewDopplerOAuthFlow(srv.URL)
	_, err := flow.Login(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty device code")
}

func TestDopplerOAuthFlow_PollNon2xx(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/auth/device":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": "c", "auth_url": srv.URL + "/approve",
				"polling_interval": 1, "expires_in": 60,
			})
		case "/v3/auth/device/token":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`forbidden`))
		}
	}))
	defer srv.Close()

	flow := auth.NewDopplerOAuthFlow(srv.URL)
	flow.PollInterval = 10 * time.Millisecond
	flow.Opener = func(context.Context, string) error { return nil }
	_, err := flow.Login(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestNewDopplerOAuthFlow_DefaultBaseURL(t *testing.T) {
	flow := auth.NewDopplerOAuthFlow("")
	assert.Equal(t, "https://api.doppler.com", flow.BaseURL)
}

func TestDopplerOAuthFlow_PollDecodeError(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/auth/device":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": "c", "auth_url": srv.URL + "/approve",
				"polling_interval": 1, "expires_in": 60,
			})
		case "/v3/auth/device/token":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{not-json`))
		}
	}))
	defer srv.Close()

	flow := auth.NewDopplerOAuthFlow(srv.URL)
	flow.PollInterval = 10 * time.Millisecond
	flow.Opener = func(context.Context, string) error { return nil }
	_, err := flow.Login(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode token")
}

func TestDopplerOAuthFlow_BuildDeviceRequestError(t *testing.T) {
	flow := auth.NewDopplerOAuthFlow("http://bad-url\x7f")
	_, err := flow.Login(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build device request")
}

func TestDopplerOAuthFlow_Expired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3/auth/device" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": "c", "auth_url": "http://x", "polling_interval": 1, "expires_in": 0,
			})
			return
		}
	}))
	defer srv.Close()

	flow := auth.NewDopplerOAuthFlow(srv.URL)
	flow.PollInterval = 10 * time.Millisecond
	flow.Opener = func(context.Context, string) error { return nil }
	_, err := flow.Login(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}
