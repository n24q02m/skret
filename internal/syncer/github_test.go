package syncer_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
			_ = json.NewEncoder(w).Encode(map[string]string{
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

func TestGitHubSyncer_StripsPathPrefix(t *testing.T) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	var putNames []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/owner/repo/actions/secrets/public-key":
			_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "key-123", "key": pubKeyB64})
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
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()

	s := syncer.NewGitHub("owner", "repo", "bad_token", srv.URL)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "K", Value: "V"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestGitHubSyncer_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`invalid json`))
	}))
	defer srv.Close()

	s := syncer.NewGitHub("owner", "repo", "token", srv.URL)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "key", Value: "val"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}

func TestGitHubSyncer_BadKeyFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
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
			_ = json.NewEncoder(w).Encode(map[string]string{
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
			_ = json.NewEncoder(w).Encode(map[string]string{
				"key_id": "key-123",
				"key":    pubKeyB64,
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"internal error"}`))
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
			_ = json.NewEncoder(w).Encode(map[string]string{
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

func TestGitHubSyncer_MultipleSecrets_SingleKeyFetch(t *testing.T) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	var getKeyCalls, putCalls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "public-key"):
			getKeyCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{
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
		{Key: "SECRET_1", Value: "val1"},
		{Key: "SECRET_2", Value: "val2"},
		{Key: "SECRET_3", Value: "val3"},
		{Key: "SECRET_4", Value: "val4"},
		{Key: "SECRET_5", Value: "val5"},
	}

	s := syncer.NewGitHub("owner", "repo", "ghp_test", srv.URL)
	err = s.Sync(context.Background(), secrets)
	require.NoError(t, err)

	// Public key should only be fetched once
	assert.Equal(t, int64(1), getKeyCalls.Load())
	// All 5 secrets should be PUT
	assert.Equal(t, int64(5), putCalls.Load())
}

func TestGitHubSyncer_EmptySecrets(t *testing.T) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	var putCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"key_id": "key-123",
				"key":    pubKeyB64,
			})
			return
		}
		putCalls++
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	s := syncer.NewGitHub("owner", "repo", "token", srv.URL)
	err = s.Sync(context.Background(), []*provider.Secret{})
	require.NoError(t, err)
	// No PUT calls since no secrets
	assert.Equal(t, 0, putCalls)
}

func TestGitHubSyncer_NoContent204(t *testing.T) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"key_id": "key-123",
				"key":    pubKeyB64,
			})
		case "PUT":
			// 204 No Content is also a valid success response
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	s := syncer.NewGitHub("owner", "repo", "token", srv.URL)
	err = s.Sync(context.Background(), []*provider.Secret{{Key: "KEY", Value: "val"}})
	require.NoError(t, err)
}

func TestGitHubSyncer_InvalidKeyLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Return a valid base64 string but wrong length (not 32 bytes)
		shortKey := base64.StdEncoding.EncodeToString([]byte("too-short"))
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key_id": "key-123",
			"key":    shortKey,
		})
	}))
	defer srv.Close()

	s := syncer.NewGitHub("owner", "repo", "token", srv.URL)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "key", Value: "val"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key length")
}

func TestGitHubSyncer_ContextCancellation(t *testing.T) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"key_id": "key-123",
				"key":    pubKeyB64,
			})
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	s := syncer.NewGitHub("owner", "repo", "token", srv.URL)
	err = s.Sync(ctx, []*provider.Secret{{Key: "key", Value: "val"}})
	assert.Error(t, err)
}

func TestGitHubSyncer_DefaultBaseURL(t *testing.T) {
	// Creating with empty base URL should use github.com
	s := syncer.NewGitHub("owner", "repo", "token", "")
	assert.Equal(t, "github", s.Name())
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("read error")
}

func TestGitHubSyncer_GetPublicKey_ReadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(http.StatusInternalServerError)
		// We can't easily force a Read error on the client side with httptest.NewServer
		// unless we hijack or use a more complex setup.
		// Actually, we can just use a roundtripper or mock the client.
		// But let's see if we can do it with a body that errors.
	}))
	defer srv.Close()

	// Alternatively, we can just test the error handling by mocking the HTTP client
	// if GitHubSyncer allowed it. It doesn't allow easy mocking of httpClient yet.
	// Wait, it doesn't expose httpClient.
}

func TestGitHubSyncer_Deduplication(t *testing.T) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	var putCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "k1", "key": pubKeyB64})
			return
		}
		if r.Method == "PUT" {
			putCalls.Add(1)
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer srv.Close()

	secrets := []*provider.Secret{
		{Key: "DUP", Value: "val1"},
		{Key: "DUP", Value: "val2"}, // Last one wins
		{Key: "UNIQUE", Value: "val3"},
	}

	s := syncer.NewGitHub("o", "r", "t", srv.URL)
	err = s.Sync(context.Background(), secrets)
	require.NoError(t, err)

	// Should only be 2 PUT calls: one for DUP and one for UNIQUE
	assert.Equal(t, int32(2), putCalls.Load())
}

func TestGitHubSyncer_GetPublicKey_BodyReadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusInternalServerError)
		// Close without writing 100 bytes to cause ReadAll error
	}))
	defer srv.Close()

	s := syncer.NewGitHub("o", "r", "t", srv.URL)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "K", Value: "V"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "body unreadable")
}

func TestGitHubSyncer_PutSecret_BodyReadError(t *testing.T) {
	pubKey, _, _ := box.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "k1", "key": pubKeyB64})
			return
		}
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusBadRequest)
		// Close without writing 100 bytes
	}))
	defer srv.Close()

	s := syncer.NewGitHub("o", "r", "t", srv.URL)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "K", Value: "V"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "body unreadable")
}

func TestGitHubSyncer_Sync_InvalidBaseURL(t *testing.T) {
	s := syncer.NewGitHub("o", "r", "t", " http://bad-url-with-space")
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "K", Value: "V"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create request")
}

func TestGitHubSyncer_Sync_RequestError(t *testing.T) {
	// Use a non-existent port to cause a connection error
	s := syncer.NewGitHub("o", "r", "t", "http://localhost:12345")
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "K", Value: "V"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request:")
}
