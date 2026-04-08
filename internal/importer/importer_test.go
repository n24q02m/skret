package importer_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/importer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDotenvImporter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := `# Database
DATABASE_URL="postgres://user:pass@host/db"
API_KEY=secret123
EMPTY=
export PREFIXED="with_export"
# Comment line
MULTI_LINE="line1\nline2"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	imp := importer.NewDotenv(path)
	assert.Equal(t, "dotenv", imp.Name())

	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)
	assert.Len(t, secrets, 5)

	m := make(map[string]string)
	for _, s := range secrets {
		m[s.Key] = s.Value
	}
	assert.Equal(t, "postgres://user:pass@host/db", m["DATABASE_URL"])
	assert.Equal(t, "secret123", m["API_KEY"])
	assert.Equal(t, "", m["EMPTY"])
	assert.Equal(t, "with_export", m["PREFIXED"])
}

func TestDopplerImporter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer dp.st.test_token", r.Header.Get("Authorization"))
		assert.Equal(t, "test-project", r.URL.Query().Get("project"))
		assert.Equal(t, "prd", r.URL.Query().Get("config"))

		resp := map[string]map[string]string{
			"DB_URL":  {"raw": "postgres://prod"},
			"API_KEY": {"raw": "sk-123"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	imp := importer.NewDoppler("dp.st.test_token", "test-project", "prd", srv.URL)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)
	assert.Len(t, secrets, 2)
}

func TestInfisicalImporter(t *testing.T) {
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
