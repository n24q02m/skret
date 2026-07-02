package syncer

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

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
