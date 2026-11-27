package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider/local"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// toolNames returns the tools/list names in their listed order.
func toolNames(t *testing.T, s *Server) []string {
	t.Helper()
	resp := call(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	result, ok := resp["result"].(map[string]any)
	require.True(t, ok, "missing result: %v", resp)
	raw, ok := result["tools"].([]any)
	require.True(t, ok, "tools must be an array, never null: %v", result)
	names := make([]string, 0, len(raw))
	for _, tr := range raw {
		names = append(names, tr.(map[string]any)["name"].(string))
	}
	return names
}

// The tool table and the config schema's closed set of tool names must not
// drift: config validation rejects names the server does not serve.
func TestToolNamesMatchConfigSchema(t *testing.T) {
	names := make([]string, 0, len(tools()))
	for _, d := range tools() {
		names = append(names, d.Name)
	}
	assert.Equal(t, config.MCPToolNames(), names)
}

// Without mcp.allowed_tools, tools/list keeps listing all 8 tools in the
// canonical order, gated write tools included, whatever mcp.allow_write
// says; a gated write tool is refused only when called.
func TestToolsListWithoutAllowedToolsListsEveryTool(t *testing.T) {
	assert.Len(t, config.MCPToolNames(), 8)
	assert.Equal(t, config.MCPToolNames(), toolNames(t, serverFor(t, writeFixture(t, twoEnvConfig, nil))))
	assert.Equal(t, config.MCPToolNames(), toolNames(t, serverFor(t, writeFixture(t, policyConfig("  allow_write: true\n"), nil))))
}

// With mcp.allowed_tools set, tools/list is the set a call can use: the
// allowlist, minus the write tools while mcp.allow_write is off.
func TestAllowedToolsListIsTheUsableSet(t *testing.T) {
	const allow = "  allowed_tools: [skret_delete, skret_get, skret_list, skret_set]\n"
	assert.Equal(t, []string{"skret_list", "skret_get"}, toolNames(t, serverFor(t, writeFixture(t, policyConfig(allow), nil))))
	assert.Equal(t, []string{"skret_list", "skret_get", "skret_set", "skret_delete"},
		toolNames(t, serverFor(t, writeFixture(t, policyConfig(allow+"  allow_write: true\n"), nil))))
}

// mcp.allowed_tools hides every other tool and denies calling it; the
// denied call never reaches the store.
func TestAllowedToolsHidesAndDeniesOtherTools(t *testing.T) {
	dir := writeFixture(t, policyConfig("  allowed_tools: [skret_status, skret_list]\n"), map[string]string{"API_KEY": devValue1})
	s, sink := auditedServer(t, dir)
	assert.Equal(t, []string{"skret_list", "skret_status"}, toolNames(t, s), "canonical order, not config order")

	for _, tool := range []string{"skret_get", "skret_doctor", "skret_env"} {
		text, isErr := toolText(t, toolCall(t, s, 3, tool, `{"key":"API_KEY"}`))
		assert.True(t, isErr, text)
		assert.Contains(t, text, tool+": tool is not permitted by mcp.allowed_tools")
		assert.Contains(t, text, "remediation:")
		assert.NotContains(t, text, devValue1)
	}
	_, err := os.Stat(filepath.Join(dir, local.AuditFileName))
	assert.True(t, os.IsNotExist(err), "a denied call never reaches the store")

	text, isErr := toolText(t, toolCall(t, s, 4, "skret_list", `{}`))
	require.False(t, isErr, text)
	assert.Equal(t, `["API_KEY"]`, text)

	recs := sink.records(t)
	require.Len(t, recs, 4)
	for _, r := range recs[:3] {
		assert.Equal(t, "tool_not_allowed", r["reason"])
	}
	assert.Equal(t, "allow", recs[3]["decision"])
}

// Listing a write tool in mcp.allowed_tools does not bypass the write gate.
func TestAllowedToolsDoesNotBypassWriteGate(t *testing.T) {
	dir := writeFixture(t, policyConfig("  allowed_tools: [skret_set]\n"), map[string]string{"API_KEY": "keep-me"})
	before := readSecretsFile(t, dir)
	s := serverFor(t, dir)
	resp := call(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	assert.Contains(t, marshalResp(t, resp), `"tools":[]`, "an empty tool list is an empty array")

	text, isErr := toolText(t, toolCall(t, s, 3, "skret_set", `{"key":"API_KEY","value":"hacked","confirm":true}`))
	assert.True(t, isErr, text)
	assert.Contains(t, text, "write operations are disabled")
	assert.Equal(t, before, readSecretsFile(t, dir))
}

// Unknown tool names stay protocol errors even under an allowlist.
func TestAllowedToolsUnknownToolIsStillProtocolError(t *testing.T) {
	s := serverFor(t, writeFixture(t, policyConfig("  allowed_tools: [skret_list]\n"), nil))
	errObj := rpcErrorOf(t, toolCall(t, s, 2, "skret_explode", `{}`))
	require.NotNil(t, errObj)
	assert.InDelta(t, float64(codeInvalidParams), errObj["code"], 0)
}

func TestKeyDecisionGlobs(t *testing.T) {
	for _, tc := range []struct {
		name            string
		allowed, denied []string
		key, want       string
	}{
		{"no policy allows everything", nil, nil, "ANY", ""},
		{"prefix glob", []string{"DB_*"}, nil, "DB_PASS", ""},
		{"matching is case-sensitive", []string{"DB_*"}, nil, "db_pass", reasonKeyNotAllowed},
		{"the whole name must match", []string{"DB_*"}, nil, "XDB_PASS", reasonKeyNotAllowed},
		{"suffix glob", []string{"*_TOKEN"}, nil, "GH_TOKEN", ""},
		{"single-character wildcard", []string{"API_?EY"}, nil, "API_KEY", ""},
		{"single-character wildcard is one character", []string{"API_?EY"}, nil, "API_KKEY", reasonKeyNotAllowed},
		{"character class", []string{"[AB]_KEY"}, nil, "B_KEY", ""},
		{"character class excludes others", []string{"[AB]_KEY"}, nil, "C_KEY", reasonKeyNotAllowed},
		{"exact name", []string{"API_KEY"}, nil, "API_KEY", ""},
		{"any listed pattern may match", []string{"DB_*", "API_KEY"}, nil, "API_KEY", ""},
		{"path segment glob", []string{"app/*"}, nil, "app/db", ""},
		{"star does not cross a slash", []string{"*"}, nil, "app/db", reasonKeyNotAllowed},
		{"denied wins over allowed", []string{"*"}, []string{"API_KEY"}, "API_KEY", reasonKeyDenied},
		{"denied glob", nil, []string{"*_TOKEN"}, "GH_TOKEN", reasonKeyDenied},
		{"denied glob is anchored", nil, []string{"*_TOKEN"}, "GH_TOKENS", ""},
		{"malformed denied pattern fails closed", nil, []string{"DB_["}, "ANY", reasonKeyDenied},
		{"malformed allowed pattern matches nothing", []string{"DB_["}, nil, "DB_[", reasonKeyNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{cfg: &config.Config{MCP: &config.MCPConfig{AllowedKeys: tc.allowed, DeniedKeys: tc.denied}}}
			assert.Equal(t, tc.want, s.keyDecision(tc.key))
		})
	}
	assert.Empty(t, (&Server{cfg: &config.Config{}}).keyDecision("ANY"), "no mcp block allows everything")
}

const keyPolicyBlock = "  allowed_keys: [\"DB_*\", API_KEY]\n  denied_keys: [\"DB_ROOT*\"]\n"

var keyPolicySecrets = map[string]string{
	"API_KEY":      "api-value-1",
	"DB_PASS":      "db-value-1",
	"DB_ROOT_PASS": "root-value-1",
	"OTHER":        "other-value-1",
}

// skret_list returns only the names the key policy admits.
func TestKeyPolicyFiltersList(t *testing.T) {
	s := serverFor(t, writeFixture(t, policyConfig(keyPolicyBlock), keyPolicySecrets))
	text, isErr := toolText(t, toolCall(t, s, 2, "skret_list", `{}`))
	require.False(t, isErr, text)
	assert.Equal(t, `["API_KEY","DB_PASS"]`, text)
}

// skret_get refuses keys outside the policy before touching the store, so
// a denied key that exists and one that does not answer alike.
func TestKeyPolicyGatesGet(t *testing.T) {
	dir := writeFixture(t, policyConfig(keyPolicyBlock), keyPolicySecrets)
	s := serverFor(t, dir)

	text, isErr := toolText(t, toolCall(t, s, 2, "skret_get", `{"key":"DB_PASS"}`))
	require.False(t, isErr, text)
	assert.Equal(t, "db-value-1", text)

	denied, isErr := toolText(t, toolCall(t, s, 3, "skret_get", `{"key":"DB_ROOT_PASS"}`))
	assert.True(t, isErr, denied)
	assert.Contains(t, denied, `key "DB_ROOT_PASS" is denied by mcp.denied_keys`)
	assert.Contains(t, denied, "remediation:")
	assert.NotContains(t, denied, "root-value-1")

	ghost, isErr := toolText(t, toolCall(t, s, 4, "skret_get", `{"key":"DB_ROOT_GHOST"}`))
	assert.True(t, isErr, ghost)
	assert.Contains(t, ghost, `key "DB_ROOT_GHOST" is denied by mcp.denied_keys`, "no existence oracle")

	other, isErr := toolText(t, toolCall(t, s, 5, "skret_get", `{"key":"OTHER"}`))
	assert.True(t, isErr, other)
	assert.Contains(t, other, `key "OTHER" is not permitted by mcp.allowed_keys`)
	assert.NotContains(t, other, "other-value-1")

	entries, _, err := local.ReadAuditLog(filepath.Join(dir, local.AuditFileName))
	require.NoError(t, err)
	require.Len(t, entries, 1, "only the admitted read reached the store")
	assert.Equal(t, []string{"DB_PASS"}, entries[0].KeyNames)
}

// Write tools obey the same key policy and leave the store untouched when
// they refuse.
func TestKeyPolicyGatesWrites(t *testing.T) {
	dir := writeFixture(t, policyConfig("  allow_write: true\n"+keyPolicyBlock), keyPolicySecrets)
	s := serverFor(t, dir)
	before := readSecretsFile(t, dir)

	for _, tc := range []struct{ tool, args, want string }{
		{"skret_set", `{"key":"DB_ROOT_PASS","value":"hacked","confirm":true}`, "is denied by mcp.denied_keys"},
		{"skret_rotate", `{"key":"DB_ROOT_PASS","value":"hacked","confirm":true}`, "is denied by mcp.denied_keys"},
		{"skret_delete", `{"key":"DB_ROOT_PASS","confirm":true}`, "is denied by mcp.denied_keys"},
		{"skret_set", `{"key":"OTHER","value":"hacked","confirm":true}`, "is not permitted by mcp.allowed_keys"},
		{"skret_delete", `{"key":"OTHER","confirm":true}`, "is not permitted by mcp.allowed_keys"},
	} {
		text, isErr := toolText(t, toolCall(t, s, 2, tc.tool, tc.args))
		assert.True(t, isErr, "%s %s", tc.tool, tc.args)
		assert.Contains(t, text, tc.want, tc.tool)
		assert.NotContains(t, text, "hacked")
		assert.Equal(t, before, readSecretsFile(t, dir), "%s must not touch the store", tc.tool)
	}

	text, isErr := toolText(t, toolCall(t, s, 3, "skret_set", `{"key":"DB_NEW","value":"fresh-1","confirm":true}`))
	require.False(t, isErr, text)
	text, isErr = toolText(t, toolCall(t, s, 4, "skret_get", `{"key":"DB_NEW"}`))
	require.False(t, isErr, text)
	assert.Equal(t, "fresh-1", text)
}

// An absent, null or empty policy keeps the behaviour of a server without
// one: every tool listed, every key listed and readable, and the write
// gate answering with its usual error.
func TestEmptyPolicyKeepsBehaviour(t *testing.T) {
	for name, cfg := range map[string]string{
		"no mcp block":   twoEnvConfig,
		"null mcp block": policyConfig(""),
		"empty mapping":  twoEnvConfig + "mcp: {}\n",
		"empty lists":    policyConfig("  allowed_tools: []\n  allowed_keys: []\n  denied_keys: []\n  allowed_envs: []\n"),
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeFixture(t, cfg, map[string]string{"API_KEY": devValue1, "app/db": "nested-value"})
			s := serverFor(t, dir)
			assert.Equal(t, config.MCPToolNames(), toolNames(t, s))

			text, isErr := toolText(t, toolCall(t, s, 2, "skret_list", `{}`))
			require.False(t, isErr, text)
			assert.Equal(t, `["API_KEY","app/db"]`, text)

			text, isErr = toolText(t, toolCall(t, s, 3, "skret_get", `{"key":"app/db"}`))
			require.False(t, isErr, text)
			assert.Equal(t, "nested-value", text)

			text, isErr = toolText(t, toolCall(t, s, 4, "skret_set", `{"key":"K","value":"v","confirm":true}`))
			assert.True(t, isErr)
			assert.Equal(t, "skret_set: write operations are disabled for this skret-mcp server\n"+
				"remediation: set mcp.allow_write: true in .skret.yaml (then restart the server) if the operator intends to allow secret mutation through MCP", text)
		})
	}
}

// skret_status reports the effective tool set and the key policy.
func TestStatusReportsToolAndKeyPolicy(t *testing.T) {
	cfg := policyConfig("  allowed_tools: [skret_status, skret_list, skret_set]\n" + keyPolicyBlock)
	s := serverFor(t, writeFixture(t, cfg, nil))
	text, isErr := toolText(t, toolCall(t, s, 2, "skret_status", `{}`))
	require.False(t, isErr, text)
	var status map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &status))
	assert.Equal(t, []any{"skret_list", "skret_status"}, status["tools"], "gated write tools are not effective")
	assert.Equal(t, []any{"DB_*", "API_KEY"}, status["allowed_keys"])
	assert.Equal(t, []any{"DB_ROOT*"}, status["denied_keys"])
	assert.NotContains(t, status, "audit_log")
}

// Without a tool or key policy, skret_status reports the same fields it
// always has.
func TestStatusWithoutPolicyKeepsItsFields(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, nil))
	text, isErr := toolText(t, toolCall(t, s, 2, "skret_status", `{}`))
	require.False(t, isErr, text)
	var status map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &status))
	keys := make([]string, 0, len(status))
	for k := range status {
		keys = append(keys, k)
	}
	assert.ElementsMatch(t, []string{"ok", "version", "env", "provider", "config_file", "allow_write", "allowed_envs", "read_only"}, keys)
}

// clientFor applies the environment policy itself, so a handler that
// skipped authorize still could not build a client outside the policy.
func TestClientForAppliesEnvPolicy(t *testing.T) {
	s := serverFor(t, writeFixture(t, policyConfig("  allowed_envs: [dev]\n"), nil))
	_, env, err := s.clientFor("prod")
	assert.Equal(t, "prod", env)
	assert.Equal(t, reasonEnvNotAllowed, denyReason(err))
	assert.Empty(t, s.clients)
}
