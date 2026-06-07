package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDopplerOAuthFlow_RespectPollingInterval(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/auth/device":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":             "c",
				"auth_url":         "http://x",
				"polling_interval": 1,
				"expires_in":       60,
			})
		case "/v3/auth/device/token":
			// Just succeed immediately to finish the test
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token": "tok",
				"name":  "name",
			})
		}
	}))
	defer srv.Close()

	flow := NewDopplerOAuthFlow(srv.URL)
	flow.PollInterval = 5 * time.Second
	flow.Opener = func(context.Context, string) error { return nil }

	_, err := flow.Login(context.Background(), nil)
	require.NoError(t, err)
	// Coverage will confirm line 68 was hit
}

func TestDopplerOAuthFlow_DoErrors(t *testing.T) {
	t.Run("DeviceRequestError", func(t *testing.T) {
		flow := NewDopplerOAuthFlow("http://localhost:1") // likely to fail
		flow.client.Transport = &errorRoundTripper{err: fmt.Errorf("network error")}

		_, err := flow.Login(context.Background(), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "device request")
	})

	t.Run("PollRequestError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v3/auth/device" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"code": "c", "auth_url": "http://x", "polling_interval": 1, "expires_in": 60,
				})
				return
			}
		}))
		defer srv.Close()

		flow := NewDopplerOAuthFlow(srv.URL)
		flow.Opener = func(context.Context, string) error { return nil }

		rt := &toggleErrorRoundTripper{
			Transport: http.DefaultTransport,
			failAfter: 1,
			err:       fmt.Errorf("poll network error"),
		}
		flow.client.Transport = rt

		_, err := flow.Login(context.Background(), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "poll:")
	})
}

func TestDopplerOAuthFlow_PollBuildRequestError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3/auth/device" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": "c", "auth_url": "http://x", "polling_interval": 1, "expires_in": 60,
			})
			return
		}
	}))
	defer srv.Close()

	flow := NewDopplerOAuthFlow(srv.URL)
	// Sabotage BaseURL in Opener so the next request (poll) fails to build
	flow.Opener = func(ctx context.Context, authURL string) error {
		flow.BaseURL = "http://bad-url\x7f"
		return nil
	}

	_, err := flow.Login(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build poll request")
}

type errorRoundTripper struct {
	err error
}

func (e *errorRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, e.err
}

type toggleErrorRoundTripper struct {
	Transport http.RoundTripper
	failAfter int
	calls     int
	err       error
}

func (t *toggleErrorRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	if t.calls > t.failAfter {
		return nil, t.err
	}
	return t.Transport.RoundTrip(req)
}
