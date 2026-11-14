package syncer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// githubSecretsServer serves a GitHub Actions secrets listing (names plus
// updated_at, the only metadata GitHub returns) and records DELETE calls.
// Any other request fails the test.
func githubSecretsServer(t *testing.T, listed map[string]string, deleteStatus int) (*httptest.Server, *[]string) {
	t.Helper()
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/actions/secrets":
			type entry struct {
				Name      string `json:"name"`
				UpdatedAt string `json:"updated_at"`
			}
			entries := make([]entry, 0, len(listed))
			for name, at := range listed {
				entries = append(entries, entry{Name: name, UpdatedAt: at})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": len(entries), "secrets": entries})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/repos/o/r/actions/secrets/"):
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/repos/o/r/actions/secrets/"))
			w.WriteHeader(deleteStatus)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &deleted
}

func TestGitHubExistingSecrets_CarriesUpdatedAt(t *testing.T) {
	srv, _ := githubSecretsServer(t, map[string]string{"OLD": "2026-07-17T01:02:03Z"}, http.StatusNoContent)
	g := NewGitHub("o", "r", "tok", srv.URL)
	p, ok := g.(Pruner)
	require.True(t, ok, "GitHubSyncer must implement Pruner")

	got, err := p.ExistingSecrets(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []TargetSecret{{Name: "OLD", UpdatedAt: "2026-07-17T01:02:03Z"}}, got)
}

func TestGitHubExistingSecrets_Paginated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type s struct {
			Name string `json:"name"`
		}
		resp := map[string]any{"total_count": 101}
		if r.URL.Query().Get("page") == "1" {
			names := make([]s, 100)
			for i := range names {
				names[i] = s{Name: fmt.Sprintf("K%03d", i)}
			}
			resp["secrets"] = names
		} else {
			resp["secrets"] = []s{{Name: "LAST"}}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	got, err := NewGitHub("o", "r", "tok", srv.URL).(Pruner).ExistingSecrets(context.Background())
	require.NoError(t, err)
	require.Len(t, got, 101)
	assert.Equal(t, "LAST", got[100].Name)
}

func TestGitHubDeleteSecret_SendsOneDelete(t *testing.T) {
	srv, deleted := githubSecretsServer(t, nil, http.StatusNoContent)
	p := NewGitHub("o", "r", "tok", srv.URL).(Pruner)

	require.NoError(t, p.DeleteSecret(context.Background(), "OLD"))
	assert.Equal(t, []string{"OLD"}, *deleted)
}

func TestGitHubDeleteSecret_AlreadyAbsentIsSuccess(t *testing.T) {
	srv, deleted := githubSecretsServer(t, nil, http.StatusNotFound)
	p := NewGitHub("o", "r", "tok", srv.URL).(Pruner)

	require.NoError(t, p.DeleteSecret(context.Background(), "GONE"))
	assert.Equal(t, []string{"GONE"}, *deleted)
}

func TestGitHubDeleteSecret_Errors(t *testing.T) {
	srv, _ := githubSecretsServer(t, nil, http.StatusForbidden)
	p := NewGitHub("o", "r", "tok", srv.URL).(Pruner)
	err := p.DeleteSecret(context.Background(), "OLD")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `github: delete "OLD"`)

	bad := NewGitHub("o", "r", "tok", "://bad").(Pruner)
	err = bad.DeleteSecret(context.Background(), "OLD")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "github: parse base url")

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	err = NewGitHub("o", "r", "tok", closed.URL).(Pruner).DeleteSecret(context.Background(), "OLD")
	require.Error(t, err)
	var recon *MutationNeedsReconciliationError
	assert.True(t, errors.As(err, &recon), "a transport failure on DELETE is ambiguous, not retried")
}

func TestOrphans_OnlyNamesAbsentFromSource(t *testing.T) {
	srv, deleted := githubSecretsServer(t, map[string]string{
		"KEEP_ME":   "2026-01-01T00:00:00Z",
		"also_kept": "2026-01-02T00:00:00Z",
		"ZED_OLD":   "2026-07-17T00:00:00Z",
		"ALPHA_OLD": "2026-07-27T00:00:00Z",
	}, http.StatusNoContent)
	g := NewGitHub("o", "r", "tok", srv.URL)

	// Source keys are matched through SecretName (last path segment), the same
	// mapping Sync writes under, and case-insensitively like FilterAbsent.
	got, err := Orphans(context.Background(), g, secretsFromKeys("/ns/prod/KEEP_ME", "/ns/prod/ALSO_KEPT"))
	require.NoError(t, err)
	assert.Equal(t, []TargetSecret{
		{Name: "ALPHA_OLD", UpdatedAt: "2026-07-27T00:00:00Z"},
		{Name: "ZED_OLD", UpdatedAt: "2026-07-17T00:00:00Z"},
	}, got, "orphans are sorted by name")
	assert.Empty(t, *deleted, "Orphans only lists; it never deletes")
}

func TestOrphans_RefusesEmptySource(t *testing.T) {
	srv, deleted := githubSecretsServer(t, map[string]string{"ANY": "2026-01-01T00:00:00Z"}, http.StatusNoContent)
	g := NewGitHub("o", "r", "tok", srv.URL)

	_, err := Orphans(context.Background(), g, nil)
	require.ErrorIs(t, err, ErrPruneEmptySource)
	assert.Empty(t, *deleted)
}

func TestOrphans_TargetWithoutPrune(t *testing.T) {
	_, err := Orphans(context.Background(), NewDotenv("out.env"), secretsFromKeys("/ns/prod/A"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `prune: target "dotenv" cannot delete secrets`)
}

func TestOrphans_ListErrorAborts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := Orphans(context.Background(), NewGitHub("o", "r", "tok", srv.URL), secretsFromKeys("/ns/prod/A"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `prune: list existing on "github"`)
}

func TestPrune_DeletesEveryOrphanInOrder(t *testing.T) {
	srv, deleted := githubSecretsServer(t, nil, http.StatusNoContent)
	g := NewGitHub("o", "r", "tok", srv.URL)

	n, err := Prune(context.Background(), g, []TargetSecret{{Name: "A_OLD"}, {Name: "B_OLD"}})
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, []string{"A_OLD", "B_OLD"}, *deleted)
}

func TestPrune_StopsAtFirstFailure(t *testing.T) {
	srv, deleted := githubSecretsServer(t, nil, http.StatusForbidden)
	g := NewGitHub("o", "r", "tok", srv.URL)

	n, err := Prune(context.Background(), g, []TargetSecret{{Name: "A_OLD"}, {Name: "B_OLD"}})
	require.Error(t, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, []string{"A_OLD"}, *deleted, "the second delete is never attempted")
}

func TestPrune_TargetWithoutPrune(t *testing.T) {
	_, err := Prune(context.Background(), NewDotenv("out.env"), []TargetSecret{{Name: "A"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `prune: target "dotenv" cannot delete secrets`)
}

func TestCanPrune(t *testing.T) {
	assert.True(t, CanPrune(NewGitHub("o", "r", "tok", "http://unused")))
	assert.False(t, CanPrune(NewDotenv("out.env")))
}
