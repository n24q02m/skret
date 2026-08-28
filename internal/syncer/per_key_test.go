package syncer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
)

// Keep the test contract local so the adapter behavior is exercised through
// the optional method rather than coupled to a concrete implementation type.
type perKeySyncerContract interface {
	SyncKey(context.Context, *provider.Secret) error
}

func TestPerKeySyncer_GitHubAdapterWritesOneKey(t *testing.T) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])
	var getCalls, putCalls atomic.Int32
	var putPath string
	var putBody []byte
	gh := NewGitHub("owner", "repo", "token", "https://github.test").(*GitHubSyncer)
	gh.httpClient.Transport = &mockTransport{roundTrip: func(req *http.Request) (*http.Response, error) {
		switch req.Method {
		case http.MethodGet:
			getCalls.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{"key_id":"id","key":"` + pubKeyB64 + `"}`))}, nil
		case http.MethodPut:
			putCalls.Add(1)
			putPath = req.URL.Path
			putBody, _ = io.ReadAll(req.Body)
			return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(stringsReader("{}"))}, nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(stringsReader("{}"))}, nil
		}
	}}

	keyer, ok := any(gh).(perKeySyncerContract)
	require.True(t, ok, "GitHub target must expose optional per-key sync")
	require.NoError(t, keyer.SyncKey(context.Background(), &provider.Secret{Key: "/prod/API_KEY", Value: "value"}))
	assert.Equal(t, int32(1), putCalls.Load())
	assert.Equal(t, "/repos/owner/repo/actions/secrets/API_KEY", putPath)
	var payload map[string]string
	require.NoError(t, json.Unmarshal(putBody, &payload))
	assert.NotEmpty(t, payload["encrypted_value"])
	assert.NotEqual(t, "value", payload["encrypted_value"], "provider value must remain encrypted")
}

func TestPerKeySyncer_CloudflareWorkerAdapterWritesOneKeyAndRetries(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := calls.Add(1)
		if attempt < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("provider body must not escape"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()
	built, err := Build([]TargetConfig{{
		Type:   "cloudflare",
		Token:  "token",
		Fields: map[string]string{"account": "account", "worker": "worker", "base_url": server.URL},
	}})
	require.NoError(t, err)
	worker, ok := built[0].(perKeySyncerContract)
	require.True(t, ok, "Cloudflare Worker target must expose optional per-key sync")

	require.NoError(t, worker.SyncKey(context.Background(), &provider.Secret{Key: "/prod/WORKER_KEY", Value: "value"}))
	assert.Equal(t, int32(3), calls.Load(), "one-key writes retain the existing retry boundary")

	pages := NewCloudflare("account", "", "pages", "token", server.URL)
	_, pagesSupportsPerKey := any(pages).(perKeySyncerContract)
	assert.False(t, pagesSupportsPerKey, "Cloudflare Pages must retain whole-patch batch semantics")
}

func stringsReader(value string) io.Reader { return bytes.NewBufferString(value) }

func TestPerKeySyncer_CloudflareWorkerRequestShapeIsValueFreeOnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		body, readErr := io.ReadAll(r.Body)
		require.NoError(t, readErr)
		require.NoError(t, json.Unmarshal(body, &payload))
		assert.Equal(t, "WORKER_KEY", payload["name"])
		assert.Equal(t, "value", payload["text"])
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"message":"sensitive remote body"}]}`))
	}))
	defer server.Close()
	built, err := Build([]TargetConfig{{
		Type:   "cloudflare",
		Token:  "token",
		Fields: map[string]string{"account": "account", "worker": "worker", "base_url": server.URL},
	}})
	require.NoError(t, err)
	keyer, ok := built[0].(perKeySyncerContract)
	require.True(t, ok, "Cloudflare Worker target must expose optional per-key sync")

	err = keyer.SyncKey(context.Background(), &provider.Secret{Key: "/prod/WORKER_KEY", Value: "value"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "sensitive remote body")
	assert.NotContains(t, err.Error(), "value")
}
