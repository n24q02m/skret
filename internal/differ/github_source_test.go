package differ

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubSource_DefaultBaseURL(t *testing.T) {
	src := NewGitHubSource("o", "r", "t", "")
	require.NotNil(t, src)
	assert.Equal(t, "github:o/r", src.Label())
}

func TestGitHubSource_Pagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		switch page {
		case "1":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"total_count":150,"secrets":[`)
			for i := range 100 {
				if i > 0 {
					fmt.Fprint(w, ",")
				}
				fmt.Fprintf(w, `{"name":"P1_%03d"}`, i)
			}
			fmt.Fprint(w, `]}`)
		case "2":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"total_count":150,"secrets":[`)
			for i := range 50 {
				if i > 0 {
					fmt.Fprint(w, ",")
				}
				fmt.Fprintf(w, `{"name":"P2_%03d"}`, i)
			}
			fmt.Fprint(w, `]}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	src := NewGitHubSource("acme", "app", "gh_test", srv.URL)
	snap, err := src.Read(context.Background())
	require.NoError(t, err)
	assert.Len(t, snap.Secrets, 150)
}

func TestGitHubSource_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{bad json`)
	}))
	defer srv.Close()

	src := NewGitHubSource("acme", "app", "gh_test", srv.URL)
	_, err := src.Read(context.Background())
	require.Error(t, err)
}

func TestGitHubSource_ListsNames_PresenceOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/acme/app/actions/secrets", r.URL.Path)
		assert.Equal(t, "token gh_test", r.Header.Get("Authorization"))
		fmt.Fprint(w, `{"total_count":2,"secrets":[{"name":"DB_URL"},{"name":"API_KEY"}]}`)
	}))
	defer srv.Close()

	src := NewGitHubSource("acme", "app", "gh_test", srv.URL)
	snap, err := src.Read(context.Background())
	require.NoError(t, err)

	assert.False(t, snap.CanReadValues)
	_, hasDB := snap.Secrets["DB_URL"]
	_, hasAPI := snap.Secrets["API_KEY"]
	assert.True(t, hasDB)
	assert.True(t, hasAPI)
	assert.Equal(t, "github:acme/app", src.Label())
}

func TestGitHubSource_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	src := NewGitHubSource("acme", "app", "bad", srv.URL)
	_, err := src.Read(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "github:acme/app")
}

func TestGitHubSource_URLParseError(t *testing.T) {
	// url.Parse fails on control characters like \x7f
	src := NewGitHubSource("o", "r", "t", "http://example.com/\x7f")
	_, err := src.Read(context.Background())
	require.Error(t, err)
}

func TestGitHubSource_ClientDoError(t *testing.T) {
	// An unreachable address will cause client.Do to fail
	src := NewGitHubSource("o", "r", "t", "http://localhost:1")
	_, err := src.Read(context.Background())
	require.Error(t, err)
}
