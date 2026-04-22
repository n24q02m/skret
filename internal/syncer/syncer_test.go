package syncer_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/syncer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDotenvSyncer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.synced")

	secrets := []*provider.Secret{
		{Key: "DB_URL", Value: "postgres://host"},
		{Key: "API_KEY", Value: "sk-123"},
	}

	s := syncer.NewDotenv(path)
	assert.Equal(t, "dotenv", s.Name())

	err := s.Sync(context.Background(), secrets)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, `API_KEY="sk-123"`)
	assert.Contains(t, content, `DB_URL="postgres://host"`)
}

func TestDotenvSyncer_WriteError(t *testing.T) {
	dir := t.TempDir()
	// Using a directory path instead of a file path will cause os.WriteFile to fail
	s := syncer.NewDotenv(dir)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "key", Value: "val"}})
	assert.Error(t, err)
}

func TestDotenvSyncer_CreateTempError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "nonexistent", "inner", ".env")
	s := syncer.NewDotenv(target)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "K", Value: "V"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create temp")
}

func TestDotenvSyncer_RenameError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	s := syncer.NewDotenv(target)
	err := s.Sync(context.Background(), []*provider.Secret{{Key: "K", Value: "V"}})
	assert.Error(t, err)
}

func TestGitHubSyncer(t *testing.T) {
	// Generate a real curve25519 keypair for the mock server
	pubKey, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	var putCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/owner/repo/actions/secrets/public-key":
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
		{Key: "DB_URL", Value: "postgres://host"},
		{Key: "API_KEY", Value: "sk-123"},
	}

	s := syncer.NewGitHub("owner", "repo", "ghp_test", srv.URL)
	assert.Equal(t, "github", s.Name())

	err = s.Sync(context.Background(), secrets)
	require.NoError(t, err)
	assert.Equal(t, 2, putCalls)
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

func TestDotenvSyncer_EmptySecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.empty")

	s := syncer.NewDotenv(path)
	err := s.Sync(context.Background(), nil)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Empty(t, string(data))
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

	var putCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	secrets := make([]*provider.Secret, 15)
	for i := range secrets {
		secrets[i] = &provider.Secret{Key: fmt.Sprintf("KEY_%d", i), Value: fmt.Sprintf("val_%d", i)}
	}

	s := syncer.NewGitHub("owner", "repo", "token", srv.URL)
	err := s.Sync(context.Background(), secrets)
	require.NoError(t, err)
	assert.Equal(t, 15, putCalls)
}

func TestDotenvSyncer_DollarSignValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.dollar")

	secrets := []*provider.Secret{
		{Key: "PATH_VAR", Value: "$HOME/bin:$PATH"},
	}

	s := syncer.NewDotenv(path)
	err := s.Sync(context.Background(), secrets)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "PATH_VAR=")
}

