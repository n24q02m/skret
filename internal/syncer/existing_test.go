package syncer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/n24q02m/skret/internal/provider"
)

func secretsFromKeys(keys ...string) []*provider.Secret {
	out := make([]*provider.Secret, 0, len(keys))
	for _, k := range keys {
		out = append(out, &provider.Secret{Key: k, Value: "v"})
	}
	return out
}

func TestGitHubExistingKeys_Paginated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/repos/o/r/actions/secrets", r.URL.Path)
		page := r.URL.Query().Get("page")
		type s struct {
			Name string `json:"name"`
		}
		resp := map[string]any{"total_count": 101}
		if page == "1" {
			names := make([]s, 100)
			for i := range names {
				names[i] = s{Name: "K" + string(rune('A'+i%26))}
			}
			resp["secrets"] = names
		} else {
			resp["secrets"] = []s{{Name: "LAST"}}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	g := NewGitHub("o", "r", "tok", srv.URL)
	l, ok := g.(ExistingLister)
	require.True(t, ok, "GitHubSyncer must implement ExistingLister")
	names, err := l.ExistingKeys(context.Background())
	require.NoError(t, err)
	assert.Contains(t, names, "LAST") // trang 2 được đọc
	assert.Len(t, names, 101)
}

func TestCloudflareExistingKeys_WorkerNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/accounts/acc/workers/scripts/wkr/secrets", r.URL.Path)
		_, _ = w.Write([]byte(`{"success":true,"result":[{"name":"A","type":"secret_text"},{"name":"B","type":"secret_text"}]}`))
	}))
	defer srv.Close()

	c := NewCloudflare("acc", "wkr", "", "tok", srv.URL)
	l, ok := c.(ExistingLister)
	require.True(t, ok)
	names, err := l.ExistingKeys(context.Background())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"A", "B"}, names)
}

func TestCloudflareExistingKeys_PagesUnsupported(t *testing.T) {
	c := NewCloudflare("acc", "", "proj", "tok", "http://unused")
	l := c.(ExistingLister)
	_, err := l.ExistingKeys(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pages")
}

func TestFilterAbsent_KeepsOnlyMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"total_count":2,"secrets":[{"name":"HAVE_ONE"},{"name":"have_two"}]}`))
	}))
	defer srv.Close()
	g := NewGitHub("o", "r", "tok", srv.URL)

	secrets := secretsFromKeys("/ns/prod/HAVE_ONE", "/ns/prod/HAVE_TWO", "/ns/prod/NEW_KEY")
	kept, skipped, err := FilterAbsent(context.Background(), g, secrets)
	require.NoError(t, err)
	assert.Equal(t, 2, skipped) // so khớp case-insensitive
	require.Len(t, kept, 1)
	assert.Equal(t, "/ns/prod/NEW_KEY", kept[0].Key)
}

func TestFilterAbsent_DotenvUnsupported(t *testing.T) {
	d := NewDotenv("out.env")
	_, _, err := FilterAbsent(context.Background(), d, secretsFromKeys("/ns/prod/A"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dotenv")
}

func TestFilterAbsent_ListErrorAborts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	g := NewGitHub("o", "r", "tok", srv.URL)
	_, _, err := FilterAbsent(context.Background(), g, secretsFromKeys("/ns/prod/A"))
	require.Error(t, err)
}

// --- ExistingKeys error branches (codecov/patch: not exercised by the happy-path tests above) ---

func TestCloudflareExistingKeys_ParseBaseURLError(t *testing.T) {
	c := NewCloudflare("acc", "wkr", "", "tok", "://bad")
	l, ok := c.(ExistingLister)
	require.True(t, ok)
	_, err := l.ExistingKeys(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cloudflare: parse base url")
}

func TestCloudflareExistingKeys_DoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	srv.Close() // closed before use: httpClient.Do must fail (connection refused)

	c := NewCloudflare("acc", "wkr", "", "tok", srv.URL)
	l, ok := c.(ExistingLister)
	require.True(t, ok)
	_, err := l.ExistingKeys(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cloudflare: list worker secrets")
}

func TestCloudflareExistingKeys_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewCloudflare("acc", "wkr", "", "tok", srv.URL)
	l, ok := c.(ExistingLister)
	require.True(t, ok)
	_, err := l.ExistingKeys(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cloudflare: list worker secrets: status 500")
}

func TestCloudflareExistingKeys_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	c := NewCloudflare("acc", "wkr", "", "tok", srv.URL)
	l, ok := c.(ExistingLister)
	require.True(t, ok)
	_, err := l.ExistingKeys(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cloudflare: decode worker secrets")
}

func TestGitHubExistingKeys_ParseBaseURLError(t *testing.T) {
	g := NewGitHub("o", "r", "tok", "://bad")
	l, ok := g.(ExistingLister)
	require.True(t, ok)
	_, err := l.ExistingKeys(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "github: parse base url")
}

func TestGitHubExistingKeys_DoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	srv.Close() // closed before use: httpClient.Do must fail (connection refused)

	g := NewGitHub("o", "r", "tok", srv.URL)
	l, ok := g.(ExistingLister)
	require.True(t, ok)
	_, err := l.ExistingKeys(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "github: list secrets")
}

func TestGitHubExistingKeys_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	g := NewGitHub("o", "r", "tok", srv.URL)
	l, ok := g.(ExistingLister)
	require.True(t, ok)
	_, err := l.ExistingKeys(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "github: decode secrets list")
}
