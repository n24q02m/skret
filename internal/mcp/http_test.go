package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateHTTPAddr(t *testing.T) {
	require.NoError(t, ValidateHTTPAddr("127.0.0.1:8787", ""))
	require.NoError(t, ValidateHTTPAddr("[::1]:8787", ""))
	require.NoError(t, ValidateHTTPAddr("localhost:8787", ""))
	require.NoError(t, ValidateHTTPAddr("0.0.0.0:8787", "secret-token"))

	assert.Error(t, ValidateHTTPAddr("0.0.0.0:8787", ""))
	assert.Error(t, ValidateHTTPAddr("192.168.1.10:8787", ""))
	assert.Error(t, ValidateHTTPAddr("invalid-no-port", "secret-token"))
}

func TestHTTPHandler_HealthzAndMethods(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, map[string]string{"API_KEY": "val"}))
	h := s.HTTPHandler("")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"ok"`)

	recPostHealth := httptest.NewRecorder()
	h.ServeHTTP(recPostHealth, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/healthz", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, recPostHealth.Code)

	recGetMCP := httptest.NewRecorder()
	h.ServeHTTP(recGetMCP, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, recGetMCP.Code)

	rec404 := httptest.NewRecorder()
	h.ServeHTTP(rec404, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/other", nil))
	assert.Equal(t, http.StatusNotFound, rec404.Code)
}

func TestHTTPHandler_AuthAndRPC(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, map[string]string{"API_KEY": "val"}))
	h := s.HTTPHandler("tok-123")

	// Missing token -> 401
	recUnauth := httptest.NewRecorder()
	h.ServeHTTP(recUnauth, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)))
	assert.Equal(t, http.StatusUnauthorized, recUnauth.Code)

	// Invalid JSON -> 400
	reqBad := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader(`{bad`))
	reqBad.Header.Set("Authorization", "Bearer tok-123")
	recBad := httptest.NewRecorder()
	h.ServeHTTP(recBad, reqBad)
	assert.Equal(t, http.StatusBadRequest, recBad.Code)

	// Wrong jsonrpc version -> 400 (request) and 202 (notification)
	reqVer := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"1.0","id":1,"method":"ping"}`))
	reqVer.Header.Set("Authorization", "Bearer tok-123")
	recVer := httptest.NewRecorder()
	h.ServeHTTP(recVer, reqVer)
	assert.Equal(t, http.StatusBadRequest, recVer.Code)

	reqVerNotif := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"1.0","method":"ping"}`))
	reqVerNotif.Header.Set("Authorization", "Bearer tok-123")
	recVerNotif := httptest.NewRecorder()
	h.ServeHTTP(recVerNotif, reqVerNotif)
	assert.Equal(t, http.StatusAccepted, recVerNotif.Code)

	// Valid notification -> 202
	reqNotif := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	reqNotif.Header.Set("Authorization", "Bearer tok-123")
	recNotif := httptest.NewRecorder()
	h.ServeHTTP(recNotif, reqNotif)
	assert.Equal(t, http.StatusAccepted, recNotif.Code)

	// Too large -> 413
	oversized := bytes.Repeat([]byte("a"), int(maxHTTPRequestBytes)+10)
	reqBig := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", bytes.NewReader(oversized))
	reqBig.Header.Set("Authorization", "Bearer tok-123")
	recBig := httptest.NewRecorder()
	h.ServeHTTP(recBig, reqBig)
	assert.Equal(t, http.StatusRequestEntityTooLarge, recBig.Code)

	// Valid tools/call -> 200
	reqCall := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"skret_list","arguments":{}}}`))
	reqCall.Header.Set("Authorization", "Bearer tok-123")
	recCall := httptest.NewRecorder()
	h.ServeHTTP(recCall, reqCall)
	assert.Equal(t, http.StatusOK, recCall.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(recCall.Body.Bytes(), &resp))
	assert.Contains(t, marshalResp(t, resp), "API_KEY")

	// Method not found -> 200 JSON-RPC error
	reqMissing := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":8,"method":"unknown"}`))
	reqMissing.Header.Set("Authorization", "Bearer tok-123")
	recMissing := httptest.NewRecorder()
	h.ServeHTTP(recMissing, reqMissing)
	assert.Equal(t, http.StatusOK, recMissing.Code)
	assert.Contains(t, recMissing.Body.String(), "method not found")
}

func TestServeHTTP_Lifecycle(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, nil))
	assert.Error(t, s.ServeHTTP(context.Background(), "0.0.0.0:0", ""))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	require.NoError(t, s.ServeHTTP(ctx, "127.0.0.1:0", ""))
}
