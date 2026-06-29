package syncer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/nacl/box"
)

type mockTransport struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	return m.roundTrip(req)
}

type errorReader struct {
	err error
}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}

func (e *errorReader) Close() error {
	return nil
}

func TestGitHubSyncer_Internal_GetPublicKey_Errors(t *testing.T) {
	g := &GitHubSyncer{
		owner:   "owner",
		repo:    "repo",
		token:   "token",
		baseURL: "http://api.github.com",
		httpClient: &http.Client{
			Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					return nil, errors.New("network error")
				},
			},
		},
	}

	_, _, err := g.getPublicKey(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network error")

	// Test parse base URL error
	g.baseURL = "http://api.github.com\x7f"
	_, _, err = g.getPublicKey(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse base url")

	// Test join path error
	g.baseURL = "http://api.github.com"
	g.owner = "%zz"
	_, _, err = g.getPublicKey(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "join path")
	g.owner = "owner"

	// Test read body error
	g.httpClient.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       &errorReader{err: errors.New("read error")},
			}, nil
		},
	}
	_, _, err = g.getPublicKey(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read error")

	// Test invalid JSON
	g.httpClient.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString("invalid json")),
			}, nil
		},
	}
	_, _, err = g.getPublicKey(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode key")
}

func TestGitHubSyncer_Internal_PutSecret_Errors(t *testing.T) {
	pubKey, _, _ := box.GenerateKey(rand.Reader)
	var recipientKey [32]byte
	copy(recipientKey[:], pubKey[:])

	g := &GitHubSyncer{
		owner:   "owner",
		repo:    "repo",
		token:   "token",
		baseURL: "http://api.github.com",
		httpClient: &http.Client{
			Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					return nil, errors.New("network error")
				},
			},
		},
	}

	err := g.putSecret(context.Background(), "name", "value", &recipientKey, "key-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network error")

	// Test read body error on failure
	g.httpClient.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       &errorReader{err: errors.New("read error")},
			}, nil
		},
	}
	err = g.putSecret(context.Background(), "name", "value", &recipientKey, "key-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read error")

	// Test join path error
	g.baseURL = "http://api.github.com"
	g.owner = "%zz"
	err = g.putSecret(context.Background(), "name", "value", &recipientKey, "key-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "join path")
	g.owner = "owner"

	// Test parse base URL error
	g.baseURL = "http://api.github.com\x7f"
	err = g.putSecret(context.Background(), "name", "value", &recipientKey, "key-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse base url")

	// Test seal error
	oldRand := randReader
	defer func() { randReader = oldRand }()
	randReader = &errorReader{err: errors.New("entropy error")}

	err = g.putSecret(context.Background(), "name", "value", &recipientKey, "key-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entropy error")
}

func TestGitHubSyncer_Internal_Sync_Errors(t *testing.T) {
	g := &GitHubSyncer{
		owner:   "owner",
		repo:    "repo",
		token:   "token",
		baseURL: "http://api.github.com",
		httpClient: &http.Client{
			Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					// Fail getPublicKey
					return nil, errors.New("get public key failed")
				},
			},
		},
	}

	err := g.Sync(context.Background(), []*provider.Secret{{Key: "key", Value: "val"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get public key failed")

	// Test decode public key error (invalid base64)
	g.httpClient.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			if req.Method == "GET" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"key_id":"id","key":"!!!"}`)),
				}, nil
			}
			return nil, nil
		},
	}
	err = g.Sync(context.Background(), []*provider.Secret{{Key: "key", Value: "val"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode public key")

	// Test invalid public key length
	g.httpClient.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			if req.Method == "GET" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"key_id":"id","key":"YQ=="}`)),
				}, nil
			}
			return nil, nil
		},
	}
	err = g.Sync(context.Background(), []*provider.Secret{{Key: "key", Value: "val"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key length")

	// Test putSecret error
	pubKey, _, _ := box.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])
	g.httpClient.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			if req.Method == "GET" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"key_id":"id","key":"` + pubKeyB64 + `"}`)),
				}, nil
			}
			return nil, errors.New("put failed")
		},
	}
	err = g.Sync(context.Background(), []*provider.Secret{{Key: "key", Value: "val"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "put failed")

	// Test context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = g.Sync(ctx, []*provider.Secret{{Key: "key", Value: "val"}})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "context canceled"))
}

func TestSealSecret_Error(t *testing.T) {
	oldRand := randReader
	defer func() { randReader = oldRand }()
	randReader = &errorReader{err: errors.New("entropy error")}

	pubKey, _, _ := box.GenerateKey(rand.Reader)
	var recipientKey [32]byte
	copy(recipientKey[:], pubKey[:])

	_, err := sealSecret("secret", &recipientKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entropy error")
}

func TestGitHubSyncer_Internal_GetPublicKey_ReadBodyError_Success(t *testing.T) {
	g := &GitHubSyncer{
		httpClient: &http.Client{
			Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       &errorReader{err: errors.New("read error")},
					}, nil
				},
			},
		},
	}
	_, _, err := g.getPublicKey(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode key")
}

func TestGitHubSyncer_Internal_PutSecret_ReadBodyError_Success(t *testing.T) {
	pubKey, _, _ := box.GenerateKey(rand.Reader)
	var recipientKey [32]byte
	copy(recipientKey[:], pubKey[:])
	g := &GitHubSyncer{
		httpClient: &http.Client{
			Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusCreated,
						Body:       &errorReader{err: errors.New("read error")},
					}, nil
				},
			},
		},
	}
	err := g.putSecret(context.Background(), "name", "value", &recipientKey, "id")
	assert.NoError(t, err)
}

func TestGitHubSyncer_Internal_Sync_ContextWait(t *testing.T) {
	pubKey, _, _ := box.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	g := &GitHubSyncer{
		httpClient: &http.Client{
			Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					if req.Method == "GET" {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`{"key_id":"id","key":"` + pubKeyB64 + `"}`)),
						}, nil
					}
					// Artificial delay
					time.Sleep(10 * time.Millisecond)
					return &http.Response{
						StatusCode: http.StatusCreated,
						Body:       io.NopCloser(bytes.NewBufferString("{}")),
					}, nil
				},
			},
		},
	}

	err := g.Sync(context.Background(), []*provider.Secret{{Key: "key", Value: "val"}})
	assert.NoError(t, err)
}

func TestNewGitHub(t *testing.T) {
	t.Run("default baseURL", func(t *testing.T) {
		s := NewGitHub("owner", "repo", "token", "").(*GitHubSyncer)
		assert.Equal(t, "owner", s.owner)
		assert.Equal(t, "repo", s.repo)
		assert.Equal(t, "token", s.token)
		assert.Equal(t, "https://api.github.com", s.baseURL)
		assert.NotNil(t, s.httpClient)
		assert.Equal(t, 30*time.Second, s.httpClient.Timeout)
	})

	t.Run("custom baseURL", func(t *testing.T) {
		customURL := "https://github.example.com/api/v3"
		s := NewGitHub("owner", "repo", "token", customURL).(*GitHubSyncer)
		assert.Equal(t, customURL, s.baseURL)
	})
}
