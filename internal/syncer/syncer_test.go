package syncer_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/syncer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubSyncer(t *testing.T) {
	// Generate a real curve25519 keypair for the mock server
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	var putCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/owner/repo/actions/secrets/public-key":
			json.NewEncoder(w).Encode(map[string]string{
				"key_id": "key-123",
				"key":    pubKeyB64,
			})
		case r.Method == "PUT":
			putCalls.Add(1)
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	secrets := []*provider.Secret{
		{Key: "DB_URL", Value: "postgres://host"},
		{Key: "API_KEY", Value: "sk-123"},
	}

	s := syncer.NewGitHub("owner", "repo", "ghp_test", srv.URL)
	assert.Equal(t, "github", s.Name())

	err = s.Sync(context.Background(), secrets)
	require.NoError(t, err)
	assert.Equal(t, int32(2), putCalls.Load())
}

// TestGitHubSyncer_StripsPathPrefix — SSM-sourced secrets have keys like
// `/repo/prod/NAME`; GitHub Actions secrets API rejects any `/` in the name.
// The syncer must strip the path prefix before issuing the PUT.
func TestGitHubSyncer_StripsPathPrefix(t *testing.T) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	var putNames []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/owner/repo/actions/secrets/public-key":
			json.NewEncoder(w).Encode(map[string]string{"key_id": "key-123", "key": pubKeyB64})
		case r.Method == "PUT":
			mu.Lock()
			putNames = append(putNames, r.URL.Path)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	secrets := []*provider.Secret{
		{Key: "/wet-mcp/prod/DOCKERHUB_TOKEN", Value: "dckr_pat_xxx"},
		{Key: "/wet-mcp/prod/CI_APP_KEY", Value: "pem..."},
	}

	s := syncer.NewGitHub("owner", "repo", "ghp_test", srv.URL)
	require.NoError(t, s.Sync(context.Background(), secrets))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, putNames, 2)
	for _, p := range putNames {
		assert.NotContains(t, p, "/wet-mcp/prod/", "PUT path must not leak SSM prefix: %s", p)
		assert.Regexp(t, `/repos/owner/repo/actions/secrets/(DOCKERHUB_TOKEN|CI_APP_KEY)$`, p)
	}
}

func TestGitHubSyncer_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()

	s := syncer.NewGitHub("owner", "repo", "bad_token", srv.URL)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "K", Value: "V"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestGitHubSyncer_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`invalid json`))
	}))
	defer srv.Close()

	s := syncer.NewGitHub("owner", "repo", "token", srv.URL)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "key", Value: "val"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}

func TestGitHubSyncer_BadKeyFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"key_id": "key-123",
			"key":    "not-a-valid-base64!!!!!!!",
		})
	}))
	defer srv.Close()

	s := syncer.NewGitHub("owner", "repo", "token", srv.URL)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "key", Value: "val"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "illegal base64 data")
}

func TestGitHubSyncer_PutError(t *testing.T) {
	pubKey, _, _ := box.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]string{
				"key_id": "key-123",
				"key":    pubKeyB64,
			})
			return
		}
		// Fail the PUT request
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	s := syncer.NewGitHub("owner", "repo", "token", srv.URL)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "key", Value: "val"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestGitHubSyncer_PutAPIError500WithBody(t *testing.T) {
	pubKey, _, _ := box.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]string{
				"key_id": "key-123",
				"key":    pubKeyB64,
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"internal error"}`))
	}))
	defer srv.Close()

	s := syncer.NewGitHub("owner", "repo", "token", srv.URL)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "K", Value: "V"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
	assert.Contains(t, err.Error(), "internal error")
}

func TestGitHubSyncer_ConcurrentManySecrets(t *testing.T) {
	pubKey, _, _ := box.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	var putCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]string{
				"key_id": "key-123",
				"key":    pubKeyB64,
			})
			return
		}
		putCalls.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	secrets := make([]*provider.Secret, 15)
	for i := range secrets {
		secrets[i] = &provider.Secret{Key: fmt.Sprintf("KEY_%d", i), Value: fmt.Sprintf("val_%d", i)}
	}

	s := syncer.NewGitHub("owner", "repo", "token", srv.URL)
	err := s.Sync(context.Background(), secrets)
	require.NoError(t, err)
	assert.Equal(t, int32(15), putCalls.Load())
}
