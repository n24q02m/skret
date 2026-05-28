package importer_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/n24q02m/skret/internal/importer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInfisicalImporter_Import(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		assert.Equal(t, "project-123", r.URL.Query().Get("workspaceId"))
		assert.Equal(t, "prod", r.URL.Query().Get("environment"))

		resp := map[string]any{
			"secrets": []map[string]string{
				{"secretKey": "DB_URL", "secretValue": "postgres://prod"},
				{"secretKey": "API_KEY", "secretValue": "key-456"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	imp := importer.NewInfisical("test-token", "project-123", "prod", srv.URL)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)
	assert.Len(t, secrets, 2)

	m := make(map[string]string)
	for _, s := range secrets {
		m[s.Key] = s.Value
	}
	assert.Equal(t, "postgres://prod", m["DB_URL"])
	assert.Equal(t, "key-456", m["API_KEY"])
}

func TestInfisicalImporter_Name(t *testing.T) {
	imp := importer.NewInfisical("token", "proj-id", "prod", "")
	assert.Equal(t, "infisical", imp.Name())
}

func TestInfisicalImporter_DefaultBaseURL(t *testing.T) {
	imp := importer.NewInfisical("token", "proj", "env", "")
	assert.NotNil(t, imp)
}

func TestInfisicalImporter_SortedOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"secrets": []map[string]string{
				{"secretKey": "Z_KEY", "secretValue": "z"},
				{"secretKey": "A_KEY", "secretValue": "a"},
				{"secretKey": "M_KEY", "secretValue": "m"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	imp := importer.NewInfisical("token", "proj", "env", srv.URL)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)
	require.Len(t, secrets, 3)
	assert.Equal(t, "A_KEY", secrets[0].Key)
	assert.Equal(t, "M_KEY", secrets[1].Key)
	assert.Equal(t, "Z_KEY", secrets[2].Key)
}

func TestInfisicalImporter_EmptySecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"secrets": []map[string]string{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	imp := importer.NewInfisical("token", "proj", "env", srv.URL)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)
	assert.Empty(t, secrets)
}

func TestInfisicalImporter_RequestHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer my-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "proj-abc", r.URL.Query().Get("workspaceId"))
		assert.Equal(t, "staging", r.URL.Query().Get("environment"))

		resp := map[string]any{"secrets": []map[string]string{}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	imp := importer.NewInfisical("my-token", "proj-abc", "staging", srv.URL)
	_, err := imp.Import(context.Background())
	require.NoError(t, err)
}

func TestInfisicalImporter_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"secrets":[]}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	imp := importer.NewInfisical("token", "proj", "env", srv.URL)
	_, err := imp.Import(ctx)
	assert.Error(t, err)
}

func TestInfisicalImporter_Import_RequestError(t *testing.T) {
	// Trigger http.NewRequestWithContext error by using an invalid URL character
	imp := importer.NewInfisical("token", "proj", "env", "http://api.infisical.com\x7f")
	_, err := imp.Import(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create request")
}

func TestInfisicalImporter_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"Unauthorized"}`))
	}))
	defer srv.Close()

	imp := importer.NewInfisical("bad_token", "proj", "prod", srv.URL)
	_, err := imp.Import(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestInfisicalImporter_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`service down`))
	}))
	defer srv.Close()

	imp := importer.NewInfisical("token", "proj", "env", srv.URL)
	_, err := imp.Import(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "503")
}

func TestInfisicalImporter_APIError_ReadBodyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message"`)) // short write to cause io.ErrUnexpectedEOF
	}))
	defer srv.Close()

	imp := importer.NewInfisical("bad_token", "proj", "prod", srv.URL)
	_, err := imp.Import(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "body unreadable")
}

func TestInfisicalImporter_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{not valid json`))
	}))
	defer srv.Close()

	imp := importer.NewInfisical("token", "proj", "env", srv.URL)
	_, err := imp.Import(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}
