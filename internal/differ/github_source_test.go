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
