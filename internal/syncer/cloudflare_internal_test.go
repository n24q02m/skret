package syncer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloudflareSyncer_Worker_PutShape(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody map[string]string
	cf := &CloudflareSyncer{
		accountID: "acc123", worker: "klprism-api", token: "cf-token",
		baseURL: "https://api.cloudflare.com/client/v4",
		httpClient: &http.Client{Transport: &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				gotPath = req.URL.Path
				gotAuth = req.Header.Get("Authorization")
				b, _ := io.ReadAll(req.Body)
				_ = json.Unmarshal(b, &gotBody)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":true}`))}, nil
			},
		}},
	}
	// bcrypt-like value with $ must survive byte-exact.
	err := cf.Sync(context.Background(), []*provider.Secret{{Key: "/a/prod/HASH", Value: "$2a$14$abc"}})
	require.NoError(t, err)
	assert.Equal(t, "/client/v4/accounts/acc123/workers/scripts/klprism-api/secrets", gotPath)
	assert.Equal(t, "Bearer cf-token", gotAuth)
	assert.Equal(t, "HASH", gotBody["name"])
	assert.Equal(t, "$2a$14$abc", gotBody["text"]) // byte-exact, no $-expansion
	assert.Equal(t, "secret_text", gotBody["type"])
}

func TestCloudflareSyncer_Worker_APIError(t *testing.T) {
	cf := &CloudflareSyncer{
		accountID: "acc", worker: "w", token: "t",
		baseURL: "https://api.cloudflare.com/client/v4",
		httpClient: &http.Client{Transport: &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(`{"errors":[{"message":"forbidden"}]}`))}, nil
			},
		}},
	}
	err := cf.Sync(context.Background(), []*provider.Secret{{Key: "K", Value: "v"}})
	require.ErrorContains(t, err, "cloudflare")
	require.ErrorContains(t, err, "403")
}

func TestNewCloudflare(t *testing.T) {
	t.Run("default baseURL", func(t *testing.T) {
		s := NewCloudflare("acc", "worker", "", "token", "").(*CloudflareSyncer)
		assert.Equal(t, "acc", s.accountID)
		assert.Equal(t, "worker", s.worker)
		assert.Equal(t, "", s.pages)
		assert.Equal(t, "token", s.token)
		assert.Equal(t, "https://api.cloudflare.com/client/v4", s.baseURL)
		assert.NotNil(t, s.httpClient)
		assert.Equal(t, 30*time.Second, s.httpClient.Timeout)
		assert.Equal(t, "cloudflare", s.Name())
	})

	t.Run("custom baseURL", func(t *testing.T) {
		customURL := "https://cf.example.com/client/v4"
		s := NewCloudflare("acc", "worker", "pages-proj", "token", customURL).(*CloudflareSyncer)
		assert.Equal(t, customURL, s.baseURL)
		assert.Equal(t, "pages-proj", s.pages)
	})
}

func TestCloudflareSyncer_Internal_Sync_EmptySecrets(t *testing.T) {
	cf := &CloudflareSyncer{
		accountID: "acc", worker: "w", token: "t",
		baseURL: "https://api.cloudflare.com/client/v4",
		httpClient: &http.Client{Transport: &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("should not be called")
			},
		}},
	}
	err := cf.Sync(context.Background(), nil)
	require.NoError(t, err)
}

func TestCloudflareSyncer_Internal_Sync_ContextCancelled(t *testing.T) {
	cf := &CloudflareSyncer{
		accountID: "acc", worker: "w", token: "t",
		baseURL: "https://api.cloudflare.com/client/v4",
		httpClient: &http.Client{Transport: &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":true}`))}, nil
			},
		}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := cf.Sync(ctx, []*provider.Secret{{Key: "K", Value: "v"}})
	require.Error(t, err)
	require.True(t, errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "context canceled"))
}

func TestCloudflareSyncer_Internal_PutWorkerSecret_Errors(t *testing.T) {
	cf := &CloudflareSyncer{
		accountID: "acc", worker: "w", token: "t",
		baseURL: "https://api.cloudflare.com/client/v4",
		httpClient: &http.Client{Transport: &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("network error")
			},
		}},
	}

	err := cf.putWorkerSecret(context.Background(), "name", "value")
	require.Error(t, err)
	require.ErrorContains(t, err, "network error")

	cf.baseURL = "https://api.cloudflare.com/client/v4\x7f"
	err = cf.putWorkerSecret(context.Background(), "name", "value")
	require.Error(t, err)
	require.ErrorContains(t, err, "parse base url")

	// Non-200 response whose body cannot be read.
	cf.baseURL = "https://api.cloudflare.com/client/v4"
	cf.httpClient.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       &errorReader{err: errors.New("read error")},
			}, nil
		},
	}
	err = cf.putWorkerSecret(context.Background(), "name", "value")
	require.Error(t, err)
	require.ErrorContains(t, err, "read error")
	require.ErrorContains(t, err, "body unreadable")
}

func TestCloudflareSyncer_Pages_PatchOnlySyncedKeys(t *testing.T) {
	var patchBody map[string]any
	var methods []string
	cf := &CloudflareSyncer{
		accountID: "acc", pages: "klprism-web", token: "t",
		baseURL: "https://api.cloudflare.com/client/v4",
		httpClient: &http.Client{Transport: &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				methods = append(methods, req.Method)
				b, _ := io.ReadAll(req.Body)
				_ = json.Unmarshal(b, &patchBody)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":true}`))}, nil
			},
		}},
	}
	err := cf.Sync(context.Background(), []*provider.Secret{{Key: "/a/prod/NEW", Value: "$val=1"}})
	require.NoError(t, err)
	assert.Equal(t, []string{http.MethodPatch}, methods) // exactly one PATCH, no GET
	prod := patchBody["deployment_configs"].(map[string]any)["production"].(map[string]any)["env_vars"].(map[string]any)
	assert.Len(t, prod, 1) // only the synced key; others preserved server-side by merge
	newVar := prod["NEW"].(map[string]any)
	assert.Equal(t, "$val=1", newVar["value"]) // byte-exact
	assert.Equal(t, "secret_text", newVar["type"])
}

func TestCloudflareSyncer_Pages_PatchError(t *testing.T) {
	cf := &CloudflareSyncer{
		accountID: "acc", pages: "proj", token: "t",
		baseURL: "https://api.cloudflare.com/client/v4",
		httpClient: &http.Client{Transport: &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(`{"errors":[{"message":"forbidden"}]}`))}, nil
			},
		}},
	}
	err := cf.Sync(context.Background(), []*provider.Secret{{Key: "K", Value: "v"}})
	require.ErrorContains(t, err, "cloudflare")
	require.ErrorContains(t, err, "403")
}

func TestCloudflareSyncer_Pages_Errors(t *testing.T) {
	cf := &CloudflareSyncer{
		accountID: "acc", pages: "proj", token: "t",
		baseURL: "https://api.cloudflare.com/client/v4",
		httpClient: &http.Client{Transport: &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("network error")
			},
		}},
	}

	err := cf.syncPages(context.Background(), []*provider.Secret{{Key: "K", Value: "v"}})
	require.Error(t, err)
	require.ErrorContains(t, err, "network error")

	cf.baseURL = "https://api.cloudflare.com/client/v4\x7f"
	err = cf.syncPages(context.Background(), []*provider.Secret{{Key: "K", Value: "v"}})
	require.Error(t, err)
	require.ErrorContains(t, err, "parse base url")

	// Non-200 response whose body cannot be read.
	cf.baseURL = "https://api.cloudflare.com/client/v4"
	cf.httpClient.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       &errorReader{err: errors.New("read error")},
			}, nil
		},
	}
	err = cf.syncPages(context.Background(), []*provider.Secret{{Key: "K", Value: "v"}})
	require.Error(t, err)
	require.ErrorContains(t, err, "read error")
	require.ErrorContains(t, err, "body unreadable")
}
