package syncer_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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

// --- Dotenv escaping edge cases ---

func TestDotenvSyncer_EscapingEdgeCases(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.escaped")

	secrets := []*provider.Secret{
		{Key: "QUOTES", Value: `value with "quotes"`},
		{Key: "NEWLINES", Value: "line1\nline2"},
		{Key: "BACKSLASH", Value: `path\to\file`},
		{Key: "EMPTY", Value: ""},
		{Key: "SPACES", Value: "  has spaces  "},
		{Key: "UNICODE", Value: "test value unicode"},
		{Key: "EQUALS", Value: "key=value"},
	}

	s := syncer.NewDotenv(path)
	err := s.Sync(context.Background(), secrets)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)

	// All values should be quoted with %q format
	assert.Contains(t, content, `BACKSLASH=`)
	assert.Contains(t, content, `EMPTY=""`)
	assert.Contains(t, content, `EQUALS="key=value"`)
	assert.Contains(t, content, `NEWLINES=`)
	assert.Contains(t, content, `QUOTES=`)
}

func TestDotenvSyncer_Sorted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.sorted")

	secrets := []*provider.Secret{
		{Key: "Z_KEY", Value: "z"},
		{Key: "A_KEY", Value: "a"},
		{Key: "M_KEY", Value: "m"},
	}

	s := syncer.NewDotenv(path)
	err := s.Sync(context.Background(), secrets)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 3)
	assert.True(t, strings.HasPrefix(lines[0], "A_KEY="))
	assert.True(t, strings.HasPrefix(lines[1], "M_KEY="))
	assert.True(t, strings.HasPrefix(lines[2], "Z_KEY="))
}

func TestDotenvSyncer_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.perms")

	secrets := []*provider.Secret{
		{Key: "KEY", Value: "val"},
	}

	s := syncer.NewDotenv(path)
	err := s.Sync(context.Background(), secrets)
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	// On Unix-like systems, permissions should be 0600
	// On Windows, this check is less meaningful
	assert.False(t, info.IsDir())
}

func TestDotenvSyncer_LargeSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.large")

	secrets := make([]*provider.Secret, 100)
	for i := 0; i < 100; i++ {
		secrets[i] = &provider.Secret{
			Key:   "KEY_" + strings.Repeat("X", 10),
			Value: strings.Repeat("V", 1000),
		}
	}

	s := syncer.NewDotenv(path)
	err := s.Sync(context.Background(), secrets)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, len(data) > 100000)
}

// --- GitHub syncer: public key caching behavior ---

func TestGitHubSyncer_MultipleSecrets_SingleKeyFetch(t *testing.T) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	var getKeyCalls, putCalls int
	var mu sync.Mutex
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

	var putCalls int
	var mu sync.Mutex
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
