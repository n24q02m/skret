package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
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

// postMCP sends one POST /mcp with the given headers.
func postMCP(t *testing.T, h http.Handler, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func httpErrorCode(t *testing.T, rec *httptest.ResponseRecorder) float64 {
	t.Helper()
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp), rec.Body.String())
	errObj := rpcErrorOf(t, resp)
	require.NotNil(t, errObj, rec.Body.String())
	return errObj["code"].(float64)
}

func b64Header(v string) string {
	return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(v)) + "?="
}

func TestHTTPHandler_ModernRequests(t *testing.T) {
	s, sink := auditedServer(t, writeFixture(t, twoEnvConfig, map[string]string{"API_KEY": "val"}))
	h := s.HTTPHandler("")
	callBody := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{` + modernMeta + `,"name":"skret_list","arguments":{}}}`
	callHeaders := func(overrides map[string]string) map[string]string {
		hdr := map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "skret_list"}
		for k, v := range overrides {
			if v == "" {
				delete(hdr, k)
				continue
			}
			hdr[k] = v
		}
		return hdr
	}

	rec := postMCP(t, h, callBody, callHeaders(map[string]string{"Mcp-Session-Id": "ignored-session"}))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"resultType":"complete"`)
	assert.Contains(t, rec.Body.String(), "API_KEY")

	rec = postMCP(t, h, callBody, callHeaders(map[string]string{"Mcp-Name": b64Header("skret_list"), "Mcp-Method": b64Header("tools/call")}))
	assert.Equal(t, http.StatusOK, rec.Code, "base64 sentinel values are decoded before comparison")
	require.Len(t, sink.records(t), 2)

	for name, hdr := range map[string]map[string]string{
		"missing protocol version header": callHeaders(map[string]string{"MCP-Protocol-Version": ""}),
		"protocol version mismatch":       callHeaders(map[string]string{"MCP-Protocol-Version": "2025-06-18"}),
		"missing method header":           callHeaders(map[string]string{"Mcp-Method": ""}),
		"method mismatch":                 callHeaders(map[string]string{"Mcp-Method": "tools/list"}),
		"missing name header":             callHeaders(map[string]string{"Mcp-Name": ""}),
		"name mismatch":                   callHeaders(map[string]string{"Mcp-Name": "skret_get"}),
		"undecodable sentinel":            callHeaders(map[string]string{"Mcp-Name": "=?base64?***?="}),
	} {
		t.Run(name, func(t *testing.T) {
			rec := postMCP(t, h, callBody, hdr)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.InDelta(t, float64(codeHeaderMismatch), httpErrorCode(t, rec), 0)
		})
	}
	assert.Len(t, sink.records(t), 2, "a request with mismatched headers never runs")

	discover := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + modernMeta + `}}`
	rec = postMCP(t, h, discover, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover"})
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"supportedVersions"`)

	unknown := `{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{` + modernMeta + `}}`
	rec = postMCP(t, h, unknown, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "resources/list"})
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.InDelta(t, float64(codeMethodNotFound), httpErrorCode(t, rec), 0)

	unsupported := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}`
	rec = postMCP(t, h, unsupported, map[string]string{"MCP-Protocol-Version": "2099-01-01", "Mcp-Method": "tools/list"})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.InDelta(t, float64(codeUnsupportedProtocolVersion), httpErrorCode(t, rec), 0)

	noCaps := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	rec = postMCP(t, h, noCaps, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.InDelta(t, float64(codeInvalidParams), httpErrorCode(t, rec), 0)

	notification := `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{` + modernMeta + `,"requestId":1}}`
	rec = postMCP(t, h, notification, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "notifications/cancelled"})
	assert.Equal(t, http.StatusAccepted, rec.Code)
	rec = postMCP(t, h, notification, map[string]string{"MCP-Protocol-Version": "2026-07-28"})
	assert.Equal(t, http.StatusBadRequest, rec.Code, "header validation applies to notifications too")
}

// Requests without per-request _meta keep the earlier transport rules:
// no Mcp-Method/Mcp-Name headers needed, JSON-RPC errors answered with 200.
func TestHTTPHandler_LegacyRequestsNeedNoNewHeaders(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, map[string]string{"API_KEY": "val"}))
	h := s.HTTPHandler("")
	rec := postMCP(t, h, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, map[string]string{"MCP-Protocol-Version": "2025-06-18"})
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"protocolVersion":"2025-06-18"`)
	rec = postMCP(t, h, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"skret_explode"}}`, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.InDelta(t, float64(codeInvalidParams), httpErrorCode(t, rec), 0)
}
