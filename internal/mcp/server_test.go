package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/provider/local"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// fixture layout helpers ------------------------------------------------------

const devValue1 = "v-dev-!@#$%" // special chars prove no quoting mangling

// writeFixture materializes a project directory: .skret.yaml with the given
// body plus a dev secrets file from the map (nil map = no file).
func writeFixture(t *testing.T, cfgYAML string, secrets map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(cfgYAML), 0o600))
	if secrets != nil {
		raw, err := yaml.Marshal(localFileShape{Version: "1", Secrets: secrets})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), raw, 0o600))
	}
	return dir
}

// localFileShape mirrors the local provider's file format for fixtures
// (kept local to the test so provider internals stay out of the wire).
type localFileShape struct {
	Version string            `yaml:"version"`
	Secrets map[string]string `yaml:"secrets"`
}

const twoEnvConfig = `version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: .secrets.dev.yaml
  prod:
    provider: local
    file: .secrets.prod.yaml
`

// serverFor builds a Server over a fixture directory.
func serverFor(t *testing.T, dir string) *Server {
	t.Helper()
	s, err := New(Options{WorkDir: dir, Version: "test-1"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// session helpers ---------------------------------------------------------------

// call sends one request line and decodes the single response line.
func call(t *testing.T, s *Server, line string) map[string]any {
	t.Helper()
	var out strings.Builder
	require.NoError(t, s.Serve(strings.NewReader(line+"\n"), &out))
	lines := nonEmptyLines(out.String())
	require.Len(t, lines, 1, "expected exactly one response line, got: %q", out.String())
	return decodeLine(t, lines[0])
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func decodeLine(t *testing.T, line string) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &m))
	return m
}

// marshalResp re-encodes a response for byte-level assertions (e.g. a value
// must not appear anywhere in a list response).
func marshalResp(t *testing.T, resp map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(resp)
	require.NoError(t, err)
	return string(raw)
}

// readSecretsFile returns the dev secrets file content for mutation checks.
func readSecretsFile(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, ".secrets.dev.yaml"))
	require.NoError(t, err)
	return string(raw)
}

// toolText extracts the first text content of a tools/call response and the
// isError flag.
func toolText(t *testing.T, resp map[string]any) (string, bool) {
	t.Helper()
	result, ok := resp["result"].(map[string]any)
	require.True(t, ok, "missing result object: %v", resp)
	isErr, _ := result["isError"].(bool)
	contents, ok := result["content"].([]any)
	require.True(t, ok, "missing content array: %v", result)
	require.NotEmpty(t, contents)
	first, ok := contents[0].(map[string]any)
	require.True(t, ok)
	text, _ := first["text"].(string)
	return text, isErr
}

// rpcErrorOf returns the error object when the response carries one.
func rpcErrorOf(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		return nil
	}
	return errObj
}

// initialize performs the handshake and the initialized notification. The
// notification must produce zero response lines.
func initialize(t *testing.T, s *Server, protocol string) map[string]any {
	t.Helper()
	line := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + protocol + `","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`
	resp := call(t, s, line)
	require.Nil(t, rpcErrorOf(t, resp))
	var out strings.Builder
	require.NoError(t, s.Serve(strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"), &out))
	require.Empty(t, out.String(), "initialized notification must never answer")
	return resp
}

// toolCall runs a tools/call on a handshake-ready server.
func toolCall(t *testing.T, s *Server, id int, name, argsJSON string) map[string]any {
	t.Helper()
	return call(t, s, `{"jsonrpc":"2.0","id":`+strconv.Itoa(id)+`,"method":"tools/call","params":{"name":"`+name+`","arguments":`+argsJSON+`}}`)
}

// Protocol tests ---------------------------------------------------------------

func TestInitialize_NegotiatesProtocolVersion(t *testing.T) {
	for _, tc := range []struct {
		client string
		want   string
	}{
		{"2024-11-05", "2024-11-05"},
		{"2025-03-26", "2025-03-26"},
		{"2025-06-18", "2025-06-18"},
		{"1999-01-01", ProtocolVersionLatest}, // unknown → server's latest
		{"", ProtocolVersionLatest},           // absent → server's latest
	} {
		t.Run(tc.client+"/"+tc.want, func(t *testing.T) {
			dir := writeFixture(t, twoEnvConfig, map[string]string{"A": "1"})
			s := serverFor(t, dir)
			params := `{"protocolVersion":"` + tc.client + `","capabilities":{},"clientInfo":{"name":"t","version":"0"}}`
			if tc.client == "" {
				params = `{}`
			}
			resp := call(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":`+params+`}`)
			result := resp["result"].(map[string]any)
			assert.Equal(t, tc.want, result["protocolVersion"])
			assert.Equal(t, "2.0", resp["jsonrpc"])
			info := result["serverInfo"].(map[string]any)
			assert.Equal(t, ServerName, info["name"])
			assert.Equal(t, "test-1", info["version"])
			caps := result["capabilities"].(map[string]any)
			assert.Contains(t, caps, "tools")
		})
	}
}

func TestInitialize_InvalidParams(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	resp := call(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":42}}`)
	errObj := rpcErrorOf(t, resp)
	require.NotNil(t, errObj)
	assert.Equal(t, float64(codeInvalidParams), errObj["code"])
}

func TestPingAnswersEmptyResult(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	resp := call(t, s, `{"jsonrpc":"2.0","id":9,"method":"ping"}`)
	assert.Equal(t, map[string]any{}, resp["result"])
	assert.Nil(t, rpcErrorOf(t, resp))
}

func TestUnknownMethodIsMethodNotFound(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	resp := call(t, s, `{"jsonrpc":"2.0","id":3,"method":"resources/list"}`)
	errObj := rpcErrorOf(t, resp)
	require.NotNil(t, errObj)
	assert.Equal(t, float64(codeMethodNotFound), errObj["code"])
	assert.Contains(t, errObj["message"], "resources/list")
}

func TestWrongJSONRPCVersionRejected(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	resp := call(t, s, `{"jsonrpc":"1.0","id":1,"method":"ping"}`)
	errObj := rpcErrorOf(t, resp)
	require.NotNil(t, errObj)
	assert.Equal(t, float64(codeInvalidRequest), errObj["code"])
}

func TestNotificationProducesNoResponse(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	var out strings.Builder
	require.NoError(t, s.Serve(strings.NewReader(
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"+
			`{"jsonrpc":"2.0","method":"notifications/unknown_xyz"}`+"\n"+
			"\n"+ // blank lines are skipped, not responses
			`{"jsonrpc":"1.0","method":"ping"}`+"\n"), &out))
	assert.Empty(t, out.String(), "notifications and blank lines must never answer")
}

func TestParseErrorContinuesStream(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	var out strings.Builder
	require.NoError(t, s.Serve(strings.NewReader(
		`{"jsonrpc":"2.0","id":`+"\n"+ // malformed line
			`{"jsonrpc":"2.0","id":2,"method":"ping"}`+"\n"), &out))
	lines := nonEmptyLines(out.String())
	require.Len(t, lines, 2, "parse error answered once, then stream continues")
	first := decodeLine(t, lines[0])
	errObj := rpcErrorOf(t, first)
	require.NotNil(t, errObj)
	assert.Equal(t, float64(codeParseError), errObj["code"])
	assert.Equal(t, nil, first["id"], "parse errors answer with null id")
	second := decodeLine(t, lines[1])
	assert.Equal(t, map[string]any{}, second["result"])
}

func TestServeEndsCleanlyAtEOF(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	var out strings.Builder
	require.NoError(t, s.Serve(strings.NewReader(""), &out))
	assert.Empty(t, out.String())
}

// tools/list -------------------------------------------------------------------

func TestToolsListShape(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	resp := call(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	result := resp["result"].(map[string]any)
	toolsRaw := result["tools"].([]any)

	byName := map[string]map[string]any{}
	for _, tr := range toolsRaw {
		tool := tr.(map[string]any)
		byName[tool["name"].(string)] = tool
	}
	for _, want := range []string{"skret_list", "skret_get", "skret_env", "skret_status", "skret_doctor", "skret_set", "skret_delete", "skret_rotate"} {
		assert.Contains(t, byName, want)
	}
	assert.Len(t, byName, 8, "no undocumented tools")
	for name, tool := range byName {
		schema := tool["inputSchema"].(map[string]any)
		assert.Equal(t, "object", schema["type"], name)
		assert.NotEmpty(t, tool["description"], name)
	}
	// Write tools declare the gate in their description.
	for _, name := range []string{"skret_set", "skret_delete", "skret_rotate"} {
		assert.Contains(t, byName[name]["description"], "allow_write", name)
	}
	// Required argument shapes.
	getRequired := byName["skret_get"]["inputSchema"].(map[string]any)["required"].([]any)
	assert.Equal(t, []any{"key"}, getRequired)
	setRequired := byName["skret_set"]["inputSchema"].(map[string]any)["required"].([]any)
	assert.ElementsMatch(t, []any{"key", "value"}, setRequired)
}

// tools/call: protocol-level errors ---------------------------------------------

func TestToolsCallUnknownToolIsProtocolError(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	resp := toolCall(t, s, 4, "skret_explode", `{}`)
	errObj := rpcErrorOf(t, resp)
	require.NotNil(t, errObj)
	assert.Equal(t, float64(codeInvalidParams), errObj["code"])
	assert.Contains(t, errObj["message"], "skret_explode")
}

func TestToolsCallEmptyNameIsProtocolError(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	resp := call(t, s, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":""}}`)
	errObj := rpcErrorOf(t, resp)
	require.NotNil(t, errObj)
	assert.Equal(t, float64(codeInvalidParams), errObj["code"])
}

// read tools on a local fixture ----------------------------------------------

func TestGetListRoundTrip(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, map[string]string{"API_KEY": devValue1, "DB_PASS": "v-dev-2"})
	s := serverFor(t, dir)
	initialize(t, s, "2025-06-18")

	// List: names only, sorted, values structurally absent.
	resp := toolCall(t, s, 2, "skret_list", `{}`)
	text, isErr := toolText(t, resp)
	require.False(t, isErr, text)
	assert.Equal(t, `["API_KEY","DB_PASS"]`, text)
	assert.NotContains(t, text, devValue1)
	assert.NotContains(t, marshalResp(t, resp), devValue1, "values must never ride along a list response")

	// Get: exact raw value.
	resp = toolCall(t, s, 3, "skret_get", `{"key":"API_KEY"}`)
	text, isErr = toolText(t, resp)
	require.False(t, isErr, text)
	assert.Equal(t, devValue1, text)
}

func TestGetMissingKeyIsToolError(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, map[string]string{"A": "1"})
	s := serverFor(t, dir)
	resp := toolCall(t, s, 2, "skret_get", `{"key":"NOPE"}`)
	text, isErr := toolText(t, resp)
	assert.True(t, isErr, text)
	assert.Contains(t, text, "not found")
}

func TestGetWithoutKeyArgIsToolErrorWithRemediation(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	resp := toolCall(t, s, 2, "skret_get", `{"key":42}`)
	text, isErr := toolText(t, resp)
	assert.True(t, isErr, text)
	assert.Contains(t, text, "remediation:")
}

func TestEnvListAndDefault(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	resp := toolCall(t, s, 2, "skret_env", `{}`)
	text, isErr := toolText(t, resp)
	require.False(t, isErr, text)
	assert.JSONEq(t, `{"environments":["dev","prod"],"default_env":"dev"}`, text)
}

func TestEnvListAppliesAllowedEnvsFilter(t *testing.T) {
	cfg := `version: "1"
default_env: dev
mcp:
  allowed_envs: [dev]
environments:
  dev:
    provider: local
    file: .secrets.dev.yaml
  prod:
    provider: local
    file: .secrets.prod.yaml
`
	dir := writeFixture(t, cfg, nil)
	s := serverFor(t, dir)
	resp := toolCall(t, s, 2, "skret_env", `{}`)
	text, isErr := toolText(t, resp)
	require.False(t, isErr, text)
	assert.JSONEq(t, `{"environments":["dev"],"default_env":"dev"}`, text)
}

func TestStatusReportsPolicy(t *testing.T) {
	cfg := `version: "1"
default_env: dev
mcp:
  allowed_envs: [dev, prod]
environments:
  dev:
    provider: local
    file: .secrets.dev.yaml
    path: /prefix/dev
  prod:
    provider: local
    file: .secrets.prod.yaml
`
	dir := writeFixture(t, cfg, nil)
	s := serverFor(t, dir)
	for _, name := range []string{"skret_status", "skret_doctor"} {
		resp := toolCall(t, s, 2, name, `{}`)
		text, isErr := toolText(t, resp)
		require.False(t, isErr, text)
		var status map[string]any
		require.NoError(t, json.Unmarshal([]byte(text), &status))
		assert.Equal(t, true, status["ok"])
		assert.Equal(t, "dev", status["env"])
		assert.Equal(t, "local", status["provider"])
		assert.Equal(t, false, status["allow_write"])
		assert.Equal(t, true, status["read_only"])
		assert.Equal(t, []any{"dev", "prod"}, status["allowed_envs"])
		assert.Contains(t, status["config_file"], ".skret.yaml")
	}
}

// env selection ------------------------------------------------------------------

func TestEnvArgumentSelectsEnvironment(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, map[string]string{"K": "dev-val"})
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".secrets.prod.yaml"),
		[]byte("version: \"1\"\nsecrets:\n  K: prod-val\n"), 0o600))
	s := serverFor(t, dir)

	resp := toolCall(t, s, 2, "skret_get", `{"key":"K","env":"prod"}`)
	text, isErr := toolText(t, resp)
	require.False(t, isErr, text)
	assert.Equal(t, "prod-val", text)

	resp = toolCall(t, s, 3, "skret_get", `{"key":"K"}`)
	text, isErr = toolText(t, resp)
	require.False(t, isErr, text)
	assert.Equal(t, "dev-val", text, "no env argument resolves the default")
}

func TestUnknownEnvIsToolError(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	resp := toolCall(t, s, 2, "skret_get", `{"key":"K","env":"ghost"}`)
	text, isErr := toolText(t, resp)
	assert.True(t, isErr, text)
	assert.Contains(t, text, "ghost")
	assert.Contains(t, text, "declared environments: dev, prod")
}

func TestNoEnvResolvableIsToolError(t *testing.T) {
	cfg := `version: "1"
environments:
  dev:
    provider: local
    file: .secrets.dev.yaml
  prod:
    provider: local
    file: .secrets.prod.yaml
`
	dir := writeFixture(t, cfg, nil)
	s := serverFor(t, dir)
	resp := toolCall(t, s, 2, "skret_list", `{}`)
	text, isErr := toolText(t, resp)
	assert.True(t, isErr, text)
	assert.Contains(t, text, "no environment selected")
	assert.Contains(t, text, "remediation:")
}

// write gate ---------------------------------------------------------------------

func TestWriteGateDefaultOff(t *testing.T) {
	for _, tool := range []string{"skret_set", "skret_delete", "skret_rotate"} {
		t.Run(tool, func(t *testing.T) {
			dir := writeFixture(t, twoEnvConfig, map[string]string{"API_KEY": devValue1})
			before := readSecretsFile(t, dir)
			s := serverFor(t, dir)
			args := `{"key":"API_KEY","value":"hacked"}`
			resp := toolCall(t, s, 2, tool, args)
			text, isErr := toolText(t, resp)
			assert.True(t, isErr, text)
			assert.Contains(t, text, "write operations are disabled")
			assert.Contains(t, text, "mcp.allow_write: true")
			assert.Equal(t, before, readSecretsFile(t, dir), "gated write must not touch the store")
		})
	}
}

func TestWriteEnabledRoundTrip(t *testing.T) {
	cfg := `version: "1"
default_env: dev
mcp:
  allow_write: true
environments:
  dev:
    provider: local
    file: .secrets.dev.yaml
`
	dir := writeFixture(t, cfg, map[string]string{"API_KEY": "old"})
	s := serverFor(t, dir)

	// set a new key
	resp := toolCall(t, s, 2, "skret_set", `{"key":"NEW_KEY","value":"new-val"}`)
	text, isErr := toolText(t, resp)
	require.False(t, isErr, text)

	// rotate mutates the value
	resp = toolCall(t, s, 3, "skret_rotate", `{"key":"API_KEY","value":"rotated-val"}`)
	text, isErr = toolText(t, resp)
	require.False(t, isErr, text)

	resp = toolCall(t, s, 4, "skret_get", `{"key":"API_KEY"}`)
	text, isErr = toolText(t, resp)
	require.False(t, isErr, text)
	assert.Equal(t, "rotated-val", text)

	// delete removes it
	resp = toolCall(t, s, 5, "skret_delete", `{"key":"NEW_KEY"}`)
	_, isErr = toolText(t, resp)
	require.False(t, isErr)
	resp = toolCall(t, s, 6, "skret_get", `{"key":"NEW_KEY"}`)
	_, isErr = toolText(t, resp)
	assert.True(t, isErr, "deleted key must not resolve")

	// the trail records the mutation ops (set/rotate/delete), not values
	entries, _, err := local.ReadAuditLog(filepath.Join(dir, local.AuditFileName))
	require.NoError(t, err)
	ops := []string{}
	for _, e := range entries {
		ops = append(ops, e.Op)
	}
	assert.Contains(t, ops, "rotate")
	assert.Contains(t, ops, "set")
	assert.Contains(t, ops, "delete")
}

func TestWriteEnabledMissingValueArgIsToolError(t *testing.T) {
	cfg := `version: "1"
default_env: dev
mcp:
  allow_write: true
environments:
  dev:
    provider: local
    file: .secrets.dev.yaml
`
	dir := writeFixture(t, cfg, nil)
	s := serverFor(t, dir)
	resp := toolCall(t, s, 2, "skret_set", `{"key":"K"}`)
	text, isErr := toolText(t, resp)
	assert.True(t, isErr, text)
	assert.Contains(t, text, "skret_set")
}

// allowed_envs enforcement ---------------------------------------------------

func TestAllowedEnvsBlocksDisallowedEnvironment(t *testing.T) {
	cfg := `version: "1"
default_env: dev
mcp:
  allowed_envs: [dev]
environments:
  dev:
    provider: local
    file: .secrets.dev.yaml
  prod:
    provider: local
    file: .secrets.prod.yaml
`
	dir := writeFixture(t, cfg, map[string]string{"K": "dev-val"})
	s := serverFor(t, dir)

	resp := toolCall(t, s, 2, "skret_get", `{"key":"K","env":"prod"}`)
	text, isErr := toolText(t, resp)
	require.True(t, isErr, text)
	assert.Contains(t, text, "not permitted by mcp.allowed_envs")
	assert.Contains(t, text, "remediation:")

	// the default env still works
	resp = toolCall(t, s, 3, "skret_get", `{"key":"K"}`)
	_, isErr = toolText(t, resp)
	assert.False(t, isErr)
}

func TestStartupEnvOutsideAllowlistFailsClosed(t *testing.T) {
	cfg := `version: "1"
default_env: dev
mcp:
  allowed_envs: [dev]
environments:
  dev:
    provider: local
    file: .secrets.dev.yaml
  prod:
    provider: local
    file: .secrets.prod.yaml
`
	dir := writeFixture(t, cfg, nil)
	_, err := New(Options{WorkDir: dir, Env: "prod"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in mcp.allowed_envs")
	assert.Contains(t, skret.RemediationOf(err), "allowed_envs")
}

// audit trail ----------------------------------------------------------------

func TestMCPReadsAreAudited(t *testing.T) {
	t.Setenv("SKRET_ACTOR", "agent-bot")
	cfg := `version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: .secrets.dev.yaml
`
	dir := writeFixture(t, cfg, map[string]string{"API_KEY": devValue1})
	s := serverFor(t, dir)

	_, isErr := toolText(t, toolCall(t, s, 2, "skret_get", `{"key":"API_KEY"}`))
	require.False(t, isErr)
	_, isErr = toolText(t, toolCall(t, s, 3, "skret_list", `{}`))
	require.False(t, isErr)

	entries, _, err := local.ReadAuditLog(filepath.Join(dir, local.AuditFileName))
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, local.AuditOpMCPRead, entries[0].Op)
	assert.Equal(t, []string{"API_KEY"}, entries[0].KeyNames)
	assert.Equal(t, "dev", entries[0].Env)
	assert.Equal(t, "agent-bot", entries[0].Actor)
	assert.Equal(t, "*", entries[1].KeyNames[0], "list reads record the wildcard scope")

	// values never reach the trail
	raw, err := os.ReadFile(filepath.Join(dir, local.AuditFileName))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), devValue1)
}

// client lifecycle ---------------------------------------------------------------

func TestClientsAreCachedPerEnvironment(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	c1, _, err := s.clientFor("dev")
	require.NoError(t, err)
	c2, _, err := s.clientFor("dev")
	require.NoError(t, err)
	assert.Same(t, c1, c2, "same environment must reuse one client")
}

func TestCloseIsIdempotent(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, nil)
	s := serverFor(t, dir)
	_, _, err := s.clientFor("dev")
	require.NoError(t, err)
	assert.NoError(t, s.Close())
	assert.NoError(t, s.Close())
}

func TestNewFailsWithoutConfig(t *testing.T) {
	_, err := New(Options{WorkDir: t.TempDir()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "discover")
	assert.NotEmpty(t, skret.RemediationOf(err))
}

func TestDeleteMissingKeyWithWriteEnabledIsToolError(t *testing.T) {
	cfg := `version: "1"
default_env: dev
mcp:
  allow_write: true
environments:
  dev:
    provider: local
    file: .secrets.dev.yaml
`
	dir := writeFixture(t, cfg, nil)
	s := serverFor(t, dir)
	resp := toolCall(t, s, 2, "skret_delete", `{"key":"GONE"}`)
	text, isErr := toolText(t, resp)
	assert.True(t, isErr, text)
	assert.Contains(t, text, "not found")
}

func TestAuditAppendFailureFailsTheReadLoudly(t *testing.T) {
	// audit_log pointing at a path that cannot be a file (its own parent is
	// a file) makes the append fail; the read must surface that, not drop
	// the entry silently.
	dir := t.TempDir()
	cfg := `version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: .secrets.dev.yaml
    audit_log: blocker/audit.log
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(cfg), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "blocker"), []byte("not a dir"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte("version: \"1\"\nsecrets:\n  K: v\n"), 0o600))

	s := serverFor(t, dir)
	resp := toolCall(t, s, 2, "skret_get", `{"key":"K"}`)
	text, isErr := toolText(t, resp)
	assert.True(t, isErr, "an unauditable read must fail: %s", text)
	assert.Contains(t, text, "audit")
}
