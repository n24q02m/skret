package syncer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitLabSyncer_UpdateShape(t *testing.T) {
	var gotPath, gotToken string
	var gotMethod string
	var gotBody map[string]any
	gl := &GitLabSyncer{
		projectID: "mygroup/myapp", token: "glpat-x", baseURL: "https://gitlab.com",
		masked: true, protected: true,
		httpClient: &http.Client{Transport: &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				gotMethod = req.Method
				gotPath = req.URL.EscapedPath()
				gotToken = req.Header.Get("PRIVATE-TOKEN")
				b, _ := io.ReadAll(req.Body)
				_ = json.Unmarshal(b, &gotBody)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			},
		}},
	}
	// Byte-exact value with $ and quotes must ride in the JSON body untouched.
	err := gl.Sync(context.Background(), []*provider.Secret{
		{Key: "/a/prod/API_KEY", Value: `v$"al@ue`},
	})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPut, gotMethod)
	// The project path must arrive URL-escaped (%2F), the key verbatim.
	assert.Equal(t, "/api/v4/projects/mygroup%2Fmyapp/variables/API_KEY", gotPath)
	assert.Equal(t, "glpat-x", gotToken)
	assert.Equal(t, "API_KEY", gotBody["key"])
	assert.Equal(t, `v$"al@ue`, gotBody["value"])
	assert.Equal(t, true, gotBody["masked"])
	assert.Equal(t, true, gotBody["protected"])
}

func TestGitLabSyncer_CreateOnMissing(t *testing.T) {
	t.Run("404 falls through to POST", func(t *testing.T) {
		var methods []string
		var postPath, postBodyKey string
		gl := &GitLabSyncer{
			projectID: "42", token: "t", baseURL: "https://gitlab.com",
			httpClient: &http.Client{Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					methods = append(methods, req.Method)
					if req.Method == http.MethodPost {
						postPath = req.URL.EscapedPath()
						var body map[string]any
						b, _ := io.ReadAll(req.Body)
						_ = json.Unmarshal(b, &body)
						postBodyKey, _ = body["key"].(string)
						assert.Equal(t, "fresh", body["value"])
					}
					if req.Method == http.MethodPut {
						return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
					}
					return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
				},
			}},
		}
		err := gl.SyncKey(context.Background(), &provider.Secret{Key: "/a/NEWVAR", Value: "fresh"})
		require.NoError(t, err)
		assert.Equal(t, []string{http.MethodPut, http.MethodPost}, methods)
		assert.Equal(t, "/api/v4/projects/42/variables", postPath)
		assert.Equal(t, "NEWVAR", postBodyKey)
	})

	t.Run("legacy 400 also falls through to POST", func(t *testing.T) {
		var methods []string
		gl := &GitLabSyncer{
			projectID: "42", token: "t", baseURL: "https://gitlab.com",
			httpClient: &http.Client{Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					methods = append(methods, req.Method)
					if req.Method == http.MethodPut {
						return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(`{"message":"variable is not found"}`))}, nil
					}
					return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
				},
			}},
		}
		require.NoError(t, gl.SyncKey(context.Background(), &provider.Secret{Key: "NEWVAR", Value: "fresh"}))
		assert.Equal(t, []string{http.MethodPut, http.MethodPost}, methods)
	})
}

func TestGitLabSyncer_TransientPUTDoesNotFallThroughToCreate(t *testing.T) {
	var calls int
	var methods []string
	gl := &GitLabSyncer{
		projectID: "42", token: "t", baseURL: "https://gitlab.com",
		httpClient: &http.Client{Transport: &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				calls++
				methods = append(methods, req.Method)
				return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			},
		}},
	}
	err := gl.SyncKey(context.Background(), &provider.Secret{Key: "K", Value: "v"})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMutationNeedsReconciliation)
	// Exactly one mutation attempt: a transient PUT cannot prove no side
	// effect, so following it with a create would risk a duplicate.
	assert.Equal(t, 1, calls)
	assert.Equal(t, []string{http.MethodPut}, methods)
}

func TestGitLabSyncer_AuthErrorCarriesRemediation(t *testing.T) {
	gl := &GitLabSyncer{
		projectID: "42", token: "bad", baseURL: "https://gitlab.com",
		httpClient: &http.Client{Transport: &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			},
		}},
	}
	err := gl.SyncKey(context.Background(), &provider.Secret{Key: "K", Value: "v"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "GITLAB_TOKEN")
	assert.ErrorContains(t, err, "403")
}

func TestGitLabSyncer_CreateMaskingErrorCarriesRemediation(t *testing.T) {
	gl := &GitLabSyncer{
		projectID: "42", token: "t", baseURL: "https://gitlab.com",
		masked: true,
		httpClient: &http.Client{Transport: &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodPut {
					return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
				}
				return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			},
		}},
	}
	err := gl.SyncKey(context.Background(), &provider.Secret{Key: "SHORT", Value: "abc"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "masking requirements")
	// The value itself must never surface in the error.
	assert.NotContains(t, err.Error(), "abc")
}

func TestGitLabSyncer_InvalidKeyRejectedBeforeHTTP(t *testing.T) {
	gl := &GitLabSyncer{
		projectID: "42", token: "t", baseURL: "https://gitlab.com",
		httpClient: &http.Client{Transport: &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("HTTP must not be called for an invalid key")
			},
		}},
	}
	for _, key := range []string{"MY-VAR", "MY.VAR", "/a/b/ HAS SPACE", ""} {
		err := gl.SyncKey(context.Background(), &provider.Secret{Key: "/a/" + key, Value: "v"})
		require.Error(t, err, "key %q must be rejected", key)
		assert.ErrorContains(t, err, "not a valid GitLab CI/CD variable name")
	}
	err := gl.SyncKey(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "nil")
}

func TestGitLabSyncer_SyncEmptyAndCollision(t *testing.T) {
	gl := &GitLabSyncer{
		projectID: "42", token: "t", baseURL: "https://gitlab.com",
		httpClient: &http.Client{Transport: &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("no HTTP expected")
			},
		}},
	}
	require.NoError(t, gl.Sync(context.Background(), nil))

	err := gl.Sync(context.Background(), []*provider.Secret{
		{Key: "/app/db/HOST", Value: "db-host-internal"},
		{Key: "/app/cache/HOST", Value: "cache-host-internal"},
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "HOST")
	assert.NotContains(t, err.Error(), "db-host-internal", "secret values must never appear in errors")
	assert.NotContains(t, err.Error(), "cache-host-internal", "secret values must never appear in errors")
}

func TestGitLabSyncer_ExistingKeys(t *testing.T) {
	t.Run("single page", func(t *testing.T) {
		var gotQuery string
		gl := &GitLabSyncer{
			projectID: "42", token: "t", baseURL: "https://gitlab.com",
			httpClient: &http.Client{Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					gotQuery = req.URL.RawQuery
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
						`[{"key":"A","value":"x"},{"key":"B","value":"y"}]`))}, nil
				},
			}},
		}
		names, err := gl.ExistingKeys(context.Background())
		require.NoError(t, err)
		assert.Equal(t, []string{"A", "B"}, names)
		assert.Contains(t, gotQuery, "per_page=100")
		assert.Contains(t, gotQuery, "page=1")
	})

	t.Run("paginates until a short page", func(t *testing.T) {
		page := 0
		gl := &GitLabSyncer{
			projectID: "42", token: "t", baseURL: "https://gitlab.com",
			httpClient: &http.Client{Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					page++
					if page == 1 {
						items := make([]string, 100)
						for i := range items {
							items[i] = fmt.Sprintf(`{"key":"K%03d"}`, i)
						}
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("[" + strings.Join(items, ",") + "]"))}, nil
					}
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[{"key":"LAST"}]`))}, nil
				},
			}},
		}
		names, err := gl.ExistingKeys(context.Background())
		require.NoError(t, err)
		assert.Len(t, names, 101)
		assert.Equal(t, "LAST", names[100])
		assert.Equal(t, 2, page)
	})
}

func TestNewGitLabFactory(t *testing.T) {
	t.Run("missing project", func(t *testing.T) {
		_, err := newGitLabFromConfig(TargetConfig{Fields: map[string]string{}, Token: "t"})
		require.ErrorContains(t, err, "project is required")
	})
	t.Run("missing token", func(t *testing.T) {
		_, err := newGitLabFromConfig(TargetConfig{Fields: map[string]string{"project": "42"}})
		require.ErrorContains(t, err, "GITLAB_TOKEN is required")
	})
	t.Run("flags default and masking parse", func(t *testing.T) {
		s, err := newGitLabFromConfig(TargetConfig{
			Fields: map[string]string{"project": "g/p", "masked": "true", "protected": "true"},
			Token:  "t",
		})
		require.NoError(t, err)
		gl := s.(*GitLabSyncer)
		assert.Equal(t, "https://gitlab.com", gl.baseURL)
		assert.True(t, gl.masked)
		assert.True(t, gl.protected)
	})
	t.Run("custom base url", func(t *testing.T) {
		s, err := newGitLabFromConfig(TargetConfig{
			Fields: map[string]string{"project": "42", "base_url": "https://gitlab.example.com"},
			Token:  "t",
		})
		require.NoError(t, err)
		assert.Equal(t, "https://gitlab.example.com", s.(*GitLabSyncer).baseURL)
	})
}
