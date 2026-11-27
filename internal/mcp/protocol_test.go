package mcp

import (
	"strconv"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var allSupportedVersions = []any{"2026-07-28", "2025-06-18", "2025-03-26", "2024-11-05"}

// modernMeta is the per-request _meta a 2026-07-28 client sends.
const modernMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"t","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}}`

// modernCall sends one stateless 2026-07-28 request; body is the params
// content besides _meta (may be empty).
func modernCall(t *testing.T, s *Server, id int, method, body string) map[string]any {
	t.Helper()
	params := "{" + modernMeta
	if body != "" {
		params += "," + body
	}
	params += "}"
	return call(t, s, `{"jsonrpc":"2.0","id":`+strconv.Itoa(id)+`,"method":"`+method+`","params":`+params+`}`)
}

func resultOf(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	require.Nil(t, rpcErrorOf(t, resp), "unexpected error: %v", resp)
	result, ok := resp["result"].(map[string]any)
	require.True(t, ok, "missing result: %v", resp)
	return result
}

func TestModernDiscover(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, nil))
	result := resultOf(t, modernCall(t, s, 1, "server/discover", ""))
	assert.Equal(t, "complete", result["resultType"])
	assert.Equal(t, allSupportedVersions, result["supportedVersions"])
	assert.Equal(t, map[string]any{"tools": map[string]any{}}, result["capabilities"])
	assert.InDelta(t, float64(0), result["ttlMs"], 0)
	assert.Equal(t, "private", result["cacheScope"])
	assert.Contains(t, result["instructions"], "skret_get")
	meta := result["_meta"].(map[string]any)
	assert.Equal(t, map[string]any{"name": ServerName, "version": "test-1"}, meta["io.modelcontextprotocol/serverInfo"])
}

// A 2026-07-28 client never initializes: tools/list and tools/call work on
// a fresh server and carry the modern result fields.
func TestModernToolsListAndCallWithoutInitialize(t *testing.T) {
	s, sink := auditedServer(t, writeFixture(t, twoEnvConfig, map[string]string{"API_KEY": devValue1}))

	list := resultOf(t, modernCall(t, s, 1, "tools/list", ""))
	assert.Equal(t, "complete", list["resultType"])
	assert.InDelta(t, float64(0), list["ttlMs"], 0)
	assert.Equal(t, "private", list["cacheScope"])
	names := []string{}
	for _, tr := range list["tools"].([]any) {
		names = append(names, tr.(map[string]any)["name"].(string))
	}
	assert.Equal(t, config.MCPToolNames(), names)
	again := resultOf(t, modernCall(t, s, 2, "tools/list", ""))
	assert.Equal(t, list["tools"], again["tools"], "deterministic order")

	got := resultOf(t, modernCall(t, s, 3, "tools/call", `"name":"skret_get","arguments":{"key":"API_KEY"}`))
	assert.Equal(t, "complete", got["resultType"])
	assert.NotContains(t, got, "isError")
	assert.Equal(t, devValue1, got["content"].([]any)[0].(map[string]any)["text"])
	assert.Contains(t, got["_meta"], "io.modelcontextprotocol/serverInfo")

	missing := resultOf(t, modernCall(t, s, 4, "tools/call", `"name":"skret_get","arguments":{"key":"NOPE"}`))
	assert.Equal(t, "complete", missing["resultType"])
	assert.Equal(t, true, missing["isError"], "execution errors stay tool results")

	errObj := rpcErrorOf(t, modernCall(t, s, 5, "tools/call", `"name":"skret_explode","arguments":{}`))
	require.NotNil(t, errObj)
	assert.InDelta(t, float64(codeInvalidParams), errObj["code"], 0)

	assert.Len(t, sink.records(t), 3, "modern tool calls are audited like legacy ones")
}

func TestModernRequestValidation(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, nil))
	for _, tc := range []struct {
		name, line string
		code       int
		contains   string
	}{
		{
			"non-string protocol version",
			`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":42,"io.modelcontextprotocol/clientCapabilities":{}}}}`,
			codeInvalidParams, "protocolVersion",
		},
		{
			"missing client capabilities",
			`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
			codeInvalidParams, "clientCapabilities",
		},
		{
			"client capabilities not an object",
			`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":"all"}}}`,
			codeInvalidParams, "clientCapabilities",
		},
		{
			// without _meta it is an initialize-era request, answered as before
			"discover without _meta",
			`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}`,
			codeMethodNotFound, "method not found: server/discover",
		},
		{
			"discover without params",
			`{"jsonrpc":"2.0","id":1,"method":"server/discover"}`,
			codeMethodNotFound, "method not found: server/discover",
		},
		{
			"ping is not a 2026-07-28 method",
			`{"jsonrpc":"2.0","id":1,"method":"ping","params":{` + modernMeta + `}}`,
			codeMethodNotFound, "ping",
		},
		{
			"initialize is not a 2026-07-28 method",
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{` + modernMeta + `}}`,
			codeMethodNotFound, "initialize",
		},
		{
			"unknown method",
			`{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{` + modernMeta + `}}`,
			codeMethodNotFound, "resources/list",
		},
		{
			"malformed tools/call params",
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{` + modernMeta + `,"name":5}}`,
			codeInvalidParams, "invalid params",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errObj := rpcErrorOf(t, call(t, s, tc.line))
			require.NotNil(t, errObj)
			assert.InDelta(t, float64(tc.code), errObj["code"], 0)
			assert.Contains(t, errObj["message"], tc.contains)
		})
	}
}

func TestModernUnsupportedVersion(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, nil))
	resp := call(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}`)
	errObj := rpcErrorOf(t, resp)
	require.NotNil(t, errObj)
	assert.InDelta(t, float64(codeUnsupportedProtocolVersion), errObj["code"], 0)
	assert.Equal(t, "Unsupported protocol version", errObj["message"])
	assert.Equal(t, map[string]any{"supported": allSupportedVersions, "requested": "2099-01-01"}, errObj["data"])
}

// A request that names an older version in _meta is served statelessly;
// only 2026-07-28 requires client capabilities.
func TestModernMetaWithOlderVersionIsServed(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, nil))
	resp := call(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18"}}}`)
	result := resultOf(t, resp)
	assert.Len(t, result["tools"], len(config.MCPToolNames()))
}

// Other _meta keys (a progress token, trace context) do not switch a
// request to 2026-07-28 semantics.
func TestLegacyMetaKeysStayLegacy(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, map[string]string{"API_KEY": devValue1}))
	resp := call(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"progressToken":"p1"},"name":"skret_list","arguments":{}}}`)
	result := resultOf(t, resp)
	assert.NotContains(t, result, "resultType")
	resp = call(t, s, `{"jsonrpc":"2.0","id":2,"method":"ping","params":{"_meta":{"traceparent":"00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"}}}`)
	assert.Equal(t, map[string]any{}, resp["result"])
}

// Legacy results keep their original shape: no resultType, no cache fields.
func TestLegacyResultShapesUnchanged(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, map[string]string{"API_KEY": devValue1}))
	initialize(t, s, "2025-06-18")
	list := resultOf(t, call(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	assert.Equal(t, []string{"tools"}, mapKeys(list))
	got := resultOf(t, toolCall(t, s, 3, "skret_get", `{"key":"API_KEY"}`))
	assert.Equal(t, []string{"content"}, mapKeys(got))
}

// A modern notification is accepted silently.
func TestModernNotificationIsSilent(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, nil))
	var out strings.Builder
	require.NoError(t, s.Serve(strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{`+modernMeta+`,"requestId":1}}`+"\n"), &out))
	assert.Empty(t, out.String())
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Params that are not an object carry no _meta: the request is served with
// the initialize-era rules and the method itself rejects the params.
func TestNonObjectParamsAreLeftToTheMethod(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, nil))
	resp := call(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["skret_list"]}`)
	errObj := rpcErrorOf(t, resp)
	require.NotNil(t, errObj)
	assert.InDelta(t, float64(codeInvalidParams), errObj["code"], 0)
}

// 2026-07-28 has no initialize handshake: a client that still initializes
// with it is answered with the newest version that has one, like any other
// version the handshake does not know.
func TestInitializeWithStatelessVersionNegotiatesHandshakeVersion(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, nil))
	result := resultOf(t, initialize(t, s, ProtocolVersionStateless))
	assert.Equal(t, ProtocolVersionLatest, result["protocolVersion"])
	assert.Equal(t, "2025-06-18", ProtocolVersionLatest)
	assert.Equal(t, "2026-07-28", ProtocolVersionStateless)
}
