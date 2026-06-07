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

func TestDopplerImporter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer dp.st.test_token", r.Header.Get("Authorization"))
		assert.Equal(t, "test-project", r.URL.Query().Get("project"))
		assert.Equal(t, "prd", r.URL.Query().Get("config"))

		resp := map[string]any{
			"secrets": map[string]map[string]string{
				"DB_URL":  {"raw": "postgres://prod"},
				"API_KEY": {"raw": "sk-123"},
			},
			"success": true,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	imp := importer.NewDoppler("dp.st.test_token", "test-project", "prd", srv.URL)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)
	assert.Len(t, secrets, 2)
}

func TestDopplerImporter_Name(t *testing.T) {
	imp := importer.NewDoppler("token", "proj", "cfg", "")
	assert.Equal(t, "doppler", imp.Name())
}

func TestDopplerImporter_DefaultBaseURL(t *testing.T) {
	imp := importer.NewDoppler("token", "proj", "cfg", "")
	assert.NotNil(t, imp)
}

func TestDopplerImporter_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"messages":["Invalid token"]}`))
	}))
	defer srv.Close()

	imp := importer.NewDoppler("bad_token", "proj", "cfg", srv.URL)
	_, err := imp.Import(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestDopplerImporter_APIError_ReadBodyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message"`)) // short write
	}))
	defer srv.Close()

	imp := importer.NewDoppler("bad_token", "proj", "prod", srv.URL)
	_, err := imp.Import(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "body unreadable")
}

func TestDopplerImporter_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json`))
	}))
	defer srv.Close()

	imp := importer.NewDoppler("token", "proj", "cfg", srv.URL)
	_, err := imp.Import(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}

func TestDopplerImporter_SortedOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"secrets": map[string]map[string]string{
				"Z_KEY": {"raw": "z"},
				"A_KEY": {"raw": "a"},
				"M_KEY": {"raw": "m"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	imp := importer.NewDoppler("token", "proj", "cfg", srv.URL)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)
	require.Len(t, secrets, 3)
	assert.Equal(t, "A_KEY", secrets[0].Key)
	assert.Equal(t, "M_KEY", secrets[1].Key)
	assert.Equal(t, "Z_KEY", secrets[2].Key)
}

func TestDopplerImporter_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"secrets": map[string]map[string]string{}})
	}))
	defer srv.Close()

	imp := importer.NewDoppler("token", "proj", "cfg", srv.URL)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)
	assert.Empty(t, secrets)
}

func TestDopplerImporter_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"messages":["Internal server error"]}`))
	}))
	defer srv.Close()

	imp := importer.NewDoppler("token", "proj", "cfg", srv.URL)
	_, err := imp.Import(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestDopplerImporter_RequestHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer dp.st.mytoken", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "myproject", r.URL.Query().Get("project"))
		assert.Equal(t, "myconfig", r.URL.Query().Get("config"))

		json.NewEncoder(w).Encode(map[string]any{"secrets": map[string]map[string]string{}})
	}))
	defer srv.Close()

	imp := importer.NewDoppler("dp.st.mytoken", "myproject", "myconfig", srv.URL)
	_, err := imp.Import(context.Background())
	require.NoError(t, err)
}

func TestDopplerImporter_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	imp := importer.NewDoppler("token", "proj", "cfg", srv.URL)
	_, err := imp.Import(ctx)
	assert.Error(t, err)
}

func TestDopplerImporter_EmptyMap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	imp := importer.NewDoppler("token", "proj", "cfg", srv.URL)
	secrets, err := imp.Import(context.Background())
	assert.NoError(t, err)
	assert.Empty(t, secrets)
}

func TestDopplerImporter_Import_RequestError(t *testing.T) {
	// Trigger parse base url error by using an invalid URL character
	imp := importer.NewDoppler("token", "proj", "cfg", "http://api.doppler.com\x7f")
	_, err := imp.Import(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse base url")
}
