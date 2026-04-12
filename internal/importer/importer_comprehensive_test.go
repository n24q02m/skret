package importer_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/importer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Dotenv edge cases ---

func TestDotenvImporter_MultiLineEscaped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := `MULTI="line1\nline2\ttab"
SINGLE_QUOTES='no expansion $VAR'
EMPTY_QUOTED=""
BARE_VALUE=just_text
NO_EQUALS_LINE
=NO_KEY
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	imp := importer.NewDotenv(path)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)

	m := make(map[string]string)
	for _, s := range secrets {
		m[s.Key] = s.Value
	}

	assert.Equal(t, `line1\nline2\ttab`, m["MULTI"])
	assert.Equal(t, "no expansion $VAR", m["SINGLE_QUOTES"])
	assert.Equal(t, "", m["EMPTY_QUOTED"])
	assert.Equal(t, "just_text", m["BARE_VALUE"])
	// "NO_EQUALS_LINE" should be skipped (no = sign)
	_, hasNoEquals := m["NO_EQUALS_LINE"]
	assert.False(t, hasNoEquals)
	// "=NO_KEY" has empty key
	_, hasEmptyKey := m[""]
	assert.True(t, hasEmptyKey)
}

func TestDotenvImporter_WithExportPrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := `export KEY1=value1
export KEY2="quoted value"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	imp := importer.NewDotenv(path)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)

	m := make(map[string]string)
	for _, s := range secrets {
		m[s.Key] = s.Value
	}
	assert.Equal(t, "value1", m["KEY1"])
	assert.Equal(t, "quoted value", m["KEY2"])
}

func TestDotenvImporter_SpecialChars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := `URL=https://host:5432/db?sslmode=require
JSON_VALUE={"key":"value"}
SPACES=  has leading and trailing
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	imp := importer.NewDotenv(path)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)

	m := make(map[string]string)
	for _, s := range secrets {
		m[s.Key] = s.Value
	}
	assert.Equal(t, "https://host:5432/db?sslmode=require", m["URL"])
	assert.Equal(t, `{"key":"value"}`, m["JSON_VALUE"])
}

func TestDotenvImporter_LargeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	var b strings.Builder
	for i := 0; i < 100; i++ {
		b.WriteString("KEY_" + strings.Repeat("A", 5) + "=value\n")
	}
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o644))

	imp := importer.NewDotenv(path)
	secrets, err := imp.Import(context.Background())
	require.NoError(t, err)
	assert.Len(t, secrets, 100)
}

// --- Doppler edge cases ---

func TestDopplerImporter_Name(t *testing.T) {
	imp := importer.NewDoppler("token", "proj", "cfg", "")
	assert.Equal(t, "doppler", imp.Name())
}

func TestDopplerImporter_DefaultBaseURL(t *testing.T) {
	// Creating with empty base URL should use default
	imp := importer.NewDoppler("token", "proj", "cfg", "")
	assert.NotNil(t, imp)
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
		resp := map[string]map[string]string{
			"Z_KEY": {"raw": "z"},
			"A_KEY": {"raw": "a"},
			"M_KEY": {"raw": "m"},
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
		json.NewEncoder(w).Encode(map[string]map[string]string{})
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

// --- Infisical edge cases ---

func TestInfisicalImporter_Name(t *testing.T) {
	imp := importer.NewInfisical("token", "proj-id", "prod", "")
	assert.Equal(t, "infisical", imp.Name())
}

func TestInfisicalImporter_DefaultBaseURL(t *testing.T) {
	imp := importer.NewInfisical("token", "proj", "env", "")
	assert.NotNil(t, imp)
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

func TestDopplerImporter_RequestHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer dp.st.mytoken", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "myproject", r.URL.Query().Get("project"))
		assert.Equal(t, "myconfig", r.URL.Query().Get("config"))

		json.NewEncoder(w).Encode(map[string]map[string]string{})
	}))
	defer srv.Close()

	imp := importer.NewDoppler("dp.st.mytoken", "myproject", "myconfig", srv.URL)
	_, err := imp.Import(context.Background())
	require.NoError(t, err)
}
