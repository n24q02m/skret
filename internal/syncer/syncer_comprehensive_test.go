package syncer_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/syncer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- GitHub syncer: public key caching behavior ---

func TestGitHubSyncer_MultipleSecrets_SingleKeyFetch(t *testing.T) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	var mu sync.Mutex
	var getKeyCalls, putCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "public-key"):
			getKeyCalls++
			json.NewEncoder(w).Encode(map[string]string{
				"key_id": "key-123",
				"key":    pubKeyB64,
			})
		case r.Method == "PUT":
			putCalls++
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

	mu.Lock()
	defer mu.Unlock()
	// Public key should only be fetched once
	assert.Equal(t, 1, getKeyCalls)
	// All 5 secrets should be PUT
	assert.Equal(t, 5, putCalls)
}

func TestGitHubSyncer_EmptySecrets(t *testing.T) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	var mu sync.Mutex
	var putCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]string{
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

	mu.Lock()
	defer mu.Unlock()
	// No PUT calls since no secrets
	assert.Equal(t, 0, putCalls)
}

func TestGitHubSyncer_NoContent204(t *testing.T) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET":
			json.NewEncoder(w).Encode(map[string]string{
				"key_id": "key-123",
				"key":    pubKeyB64,
			})
		case r.Method == "PUT":
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
		json.NewEncoder(w).Encode(map[string]string{
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
			json.NewEncoder(w).Encode(map[string]string{
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
