package importer_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/n24q02m/skret/internal/importer"
	"github.com/stretchr/testify/assert"
)

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

func TestInfisicalImporter_Import_RequestError(t *testing.T) {
	// Trigger http.NewRequestWithContext error by using an invalid URL character
	imp := importer.NewInfisical("token", "proj", "env", "http://app.infisical.com\x7f")
	_, err := imp.Import(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create request")
}

func TestInfisicalImporter_Import_DoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	imp := importer.NewInfisical("token", "proj", "env", srv.URL)
	_, err := imp.Import(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request")
}
