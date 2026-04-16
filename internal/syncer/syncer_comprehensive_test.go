package syncer_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/syncer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubSyncer_MultipleSecrets_SingleKeyFetch(t *testing.T) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	var mu sync.Mutex
	var getKeyCalls, putCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "public-key"):
			mu.Lock()
			getKeyCalls++
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]string{
				"key_id": "key-123",
				"key":    pubKeyB64,
			})
		case r.Method == "PUT":
			mu.Lock()
			putCalls++
			mu.Unlock()
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
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]string{
				"key_id": "key-123",
				"key":    pubKeyB64,
			})
			return
		}
		mu.Lock()
		putCalls++
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	s := syncer.NewGitHub("owner", "repo", "token", srv.URL)
	err = s.Sync(context.Background(), []*provider.Secret{})
	require.NoError(t, err)

	assert.Equal(t, 0, putCalls)
}

func TestGitHubSyncer_BulkSync_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()

	s := syncer.NewGitHub("owner", "repo", "token", srv.URL)
	secrets := []*provider.Secret{{Key: "K", Value: "V"}}
	err := s.Sync(context.Background(), secrets)
	assert.Error(t, err)
}

func TestGitHubSyncer_ParallelExecution(t *testing.T) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	var mu sync.Mutex
	var putCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]string{
				"key_id": "key-123",
				"key":    pubKeyB64,
			})
			return
		}
		mu.Lock()
		putCalls++
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	s := syncer.NewGitHub("owner", "repo", "token", srv.URL)

	count := 20
	secrets := make([]*provider.Secret, count)
	for i := 0; i < count; i++ {
		secrets[i] = &provider.Secret{Key: filepath.Join("DIR", strings.Repeat("K", i+1)), Value: "V"}
	}

	err = s.Sync(context.Background(), secrets)
	require.NoError(t, err)
	assert.Equal(t, count, putCalls)
}
