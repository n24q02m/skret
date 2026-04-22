package importer_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/n24q02m/skret/internal/importer"
	"github.com/stretchr/testify/assert"
)

func TestDopplerImporter_BadJSON_Decode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`not valid json`))
	}))
	defer srv.Close()

	imp := importer.NewDoppler("token", "proj", "cfg", srv.URL)
	_, err := imp.Import(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
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

func TestInfisicalImporter_BadJSON_Decode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`not valid json`))
	}))
	defer srv.Close()

	imp := importer.NewInfisical("token", "proj", "prod", srv.URL)
	_, err := imp.Import(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
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
