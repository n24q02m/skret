package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditSink stands in for stderr: a concurrency-safe buffer the server
// writes its audit JSON lines to.
type auditSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (a *auditSink) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.buf.Write(p)
}

func (a *auditSink) String() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.buf.String()
}

// records decodes every audit line written so far.
func (a *auditSink) records(t *testing.T) []map[string]any {
	t.Helper()
	return decodeJSONLines(t, a.String())
}

func decodeJSONLines(t *testing.T, raw string) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m), "audit line is not JSON: %q", line)
		out = append(out, m)
	}
	require.NoError(t, sc.Err())
	return out
}

// auditedServer builds a Server whose audit trail is captured.
func auditedServer(t *testing.T, dir string) (*Server, *auditSink) {
	t.Helper()
	sink := &auditSink{}
	s, err := New(Options{WorkDir: dir, Version: "test-1", AuditWriter: sink})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s, sink
}

// policyConfig is the two-environment local project with an mcp block.
func policyConfig(mcpBlock string) string {
	return twoEnvConfig + "mcp:\n" + mcpBlock
}

func TestAuditRecordFields(t *testing.T) {
	const value = "postgres-value-1"
	dir := writeFixture(t, twoEnvConfig, map[string]string{"DATABASE_URL": value})
	s, sink := auditedServer(t, dir)

	text, isErr := toolText(t, toolCall(t, s, 2, "skret_get", `{"key":"DATABASE_URL"}`))
	require.False(t, isErr, text)

	recs := sink.records(t)
	require.Len(t, recs, 1)
	r := recs[0]
	assert.Equal(t, "mcp_tool_call", r["event"])
	assert.Regexp(t, regexp.MustCompile(`^[0-9a-f]{32}$`), r["session_id"])
	assert.Equal(t, "skret_get", r["tool"])
	assert.Equal(t, "dev", r["env"])
	assert.Equal(t, []any{"DATA..._URL"}, r["keys"], "key names are masked")
	assert.Equal(t, "allow", r["decision"])
	assert.Equal(t, "ok", r["outcome"])
	assert.NotContains(t, r, "reason", "an allowed call carries no deny reason")
	ts, err := time.Parse(time.RFC3339Nano, r["timestamp"].(string))
	require.NoError(t, err)
	assert.Equal(t, time.UTC, ts.Location())
	assert.WithinDuration(t, time.Now(), ts, time.Minute)

	raw := sink.String()
	assert.NotContains(t, raw, value, "values never reach the audit trail")
	assert.NotContains(t, raw, "DATABASE_URL", "key names are masked in the audit trail")
}

// Every tools/call produces exactly one record, whatever its outcome, and
// every record of one server run shares its session id. Other methods are
// not tool calls and produce none.
func TestAuditOneRecordPerToolCall(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, map[string]string{"API_KEY": devValue1})
	s, sink := auditedServer(t, dir)

	initialize(t, s, "2025-06-18")
	call(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	call(t, s, `{"jsonrpc":"2.0","id":3,"method":"ping"}`)
	assert.Empty(t, sink.String(), "non-tool methods are not audited")

	toolCall(t, s, 4, "skret_list", `{}`)
	toolCall(t, s, 5, "skret_env", `{}`)
	toolCall(t, s, 6, "skret_status", `{}`)
	toolCall(t, s, 7, "skret_explode", `{}`)
	call(t, s, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":5}}`)

	recs := sink.records(t)
	require.Len(t, recs, 5)
	tools := make([]any, 0, len(recs))
	for _, r := range recs {
		tools = append(tools, r["tool"])
		assert.Equal(t, recs[0]["session_id"], r["session_id"])
	}
	assert.Equal(t, []any{"skret_list", "skret_env", "skret_status", "skret_explode", ""}, tools)
	assert.Equal(t, []any{"*"}, recs[0]["keys"], "a list records the wildcard scope")
	assert.NotContains(t, recs[1], "keys", "skret_env touches no key")
	assert.Equal(t, "unknown_tool", recs[3]["reason"])
	assert.Equal(t, "invalid_params", recs[4]["reason"])

	other, otherSink := auditedServer(t, dir)
	toolCall(t, other, 2, "skret_env", `{}`)
	assert.NotEqual(t, recs[0]["session_id"], otherSink.records(t)[0]["session_id"], "each server run is its own session")
}

func TestAuditDenyReasons(t *testing.T) {
	writeOn := "  allow_write: true\n"
	for _, tc := range []struct {
		name, mcpBlock, tool, args string
		wantReason, wantEnv        string
		wantKeys                   []any
	}{
		{"unknown tool", "", "skret_explode", `{}`, "unknown_tool", "", nil},
		{"tool outside allowed_tools", "  allowed_tools: [skret_list]\n", "skret_get", `{"key":"K"}`, "tool_not_allowed", "", nil},
		{"write disabled", "  allowed_envs: [dev, prod]\n", "skret_set", `{"key":"K","value":"new-value","confirm":true}`, "write_disabled", "", nil},
		{"env outside allowed_envs", "  allowed_envs: [dev]\n", "skret_get", `{"key":"K","env":"prod"}`, "env_not_allowed", "prod", []any{"***"}},
		{"undeclared env", "", "skret_get", `{"key":"K","env":"ghost"}`, "env_unknown", "ghost", []any{"***"}},
		{"denied key", "  denied_keys: [K]\n", "skret_get", `{"key":"K"}`, "key_denied", "dev", []any{"***"}},
		{"key outside allowed_keys", "  allowed_keys: [\"A*\"]\n", "skret_get", `{"key":"K"}`, "key_not_allowed", "dev", []any{"***"}},
		{"wrong-typed argument", "", "skret_get", `{"key":42}`, "invalid_arguments", "", nil},
		{"write without confirm", writeOn, "skret_set", `{"key":"K","value":"new-value"}`, "confirm_required", "", []any{"***"}},
		{"denied key on write", writeOn + "  denied_keys: [K]\n", "skret_delete", `{"key":"K","confirm":true}`, "key_denied", "dev", []any{"***"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFixture(t, policyConfig(tc.mcpBlock), map[string]string{"K": "stored-value"})
			s, sink := auditedServer(t, dir)
			toolCall(t, s, 2, tc.tool, tc.args)
			recs := sink.records(t)
			require.Len(t, recs, 1)
			r := recs[0]
			assert.Equal(t, "deny", r["decision"])
			assert.Equal(t, tc.wantReason, r["reason"])
			assert.Equal(t, "error", r["outcome"])
			assert.Equal(t, tc.tool, r["tool"])
			if tc.wantEnv == "" {
				assert.NotContains(t, r, "env")
			} else {
				assert.Equal(t, tc.wantEnv, r["env"])
			}
			if tc.wantKeys == nil {
				assert.NotContains(t, r, "keys")
			} else {
				assert.Equal(t, tc.wantKeys, r["keys"])
			}
			assert.NotContains(t, sink.String(), "stored-value")
			assert.NotContains(t, sink.String(), "new-value")
		})
	}
}

// A call that passes every policy check but fails in the store is an
// allowed call with an error outcome.
func TestAuditAllowedCallWithErrorOutcome(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, map[string]string{"A": "1"})
	s, sink := auditedServer(t, dir)
	_, isErr := toolText(t, toolCall(t, s, 2, "skret_get", `{"key":"NOPE"}`))
	require.True(t, isErr)
	recs := sink.records(t)
	require.Len(t, recs, 1)
	assert.Equal(t, "allow", recs[0]["decision"])
	assert.Equal(t, "error", recs[0]["outcome"])
	assert.NotContains(t, recs[0], "reason")
}

// mcp.audit_log appends the same records to a file (anchored at the config
// directory) in addition to stderr.
func TestAuditFileSink(t *testing.T) {
	dir := writeFixture(t, policyConfig("  audit_log: trails/mcp-audit.log\n"), map[string]string{"K": "stored-value"})
	s, sink := auditedServer(t, dir)
	toolCall(t, s, 2, "skret_get", `{"key":"K"}`)
	toolCall(t, s, 3, "skret_get", `{"key":"K","env":"ghost"}`)

	path := filepath.Join(dir, "trails", "mcp-audit.log")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, sink.String(), string(raw), "file and stderr carry the same records")
	assert.Len(t, decodeJSONLines(t, string(raw)), 2)
	assert.NotContains(t, string(raw), "stored-value")

	text, _ := toolText(t, toolCall(t, s, 4, "skret_status", `{}`))
	var status map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &status))
	assert.Equal(t, path, status["audit_log"])
}

// An audit file that cannot be opened fails the server at startup, before
// any tool call runs unaudited.
func TestAuditFileUnwritableAtStartupFailsClosed(t *testing.T) {
	dir := writeFixture(t, policyConfig("  audit_log: blocker/mcp.log\n"), nil)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "blocker"), []byte("not a dir"), 0o600))
	_, err := New(Options{WorkDir: dir, AuditWriter: &auditSink{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mcp.audit_log")
	assert.Contains(t, skret.RemediationOf(err), "mcp.audit_log")
}

// When the audit file becomes unwritable mid-session, the call fails
// loudly and its result (here a secret value) is withheld.
func TestAuditFileFailureFailsTheCall(t *testing.T) {
	dir := writeFixture(t, policyConfig("  audit_log: trail/mcp.log\n"), map[string]string{"K": "stored-value"})
	s, _ := auditedServer(t, dir)
	require.NoError(t, os.RemoveAll(filepath.Join(dir, "trail")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "trail"), []byte("not a dir"), 0o600))

	text, isErr := toolText(t, toolCall(t, s, 2, "skret_get", `{"key":"K"}`))
	assert.True(t, isErr, text)
	assert.Contains(t, text, "audit record")
	assert.Contains(t, text, "remediation:")
	assert.NotContains(t, text, "stored-value")
}

// stderr is best effort: a closed stderr never fails a tool call.
func TestAuditStderrFailureDoesNotFailTheCall(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, map[string]string{"K": "stored-value"})
	w := &failingWriter{}
	s, err := New(Options{WorkDir: dir, AuditWriter: w})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	text, isErr := toolText(t, toolCall(t, s, 2, "skret_get", `{"key":"K"}`))
	require.False(t, isErr, text)
	assert.Equal(t, "stored-value", text)
	assert.Equal(t, 1, w.writes)
}

// The audit trail never shares stdout with the protocol stream.
func TestAuditNeverWritesToStdout(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, map[string]string{"K": "stored-value"})
	s, sink := auditedServer(t, dir)
	var out strings.Builder
	in := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"skret_list","arguments":{}}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"skret_get","arguments":{"key":"K","env":"ghost"}}}` + "\n"
	require.NoError(t, s.Serve(strings.NewReader(in), &out))
	lines := nonEmptyLines(out.String())
	require.Len(t, lines, 2)
	for _, l := range lines {
		m := decodeLine(t, l)
		assert.Equal(t, "2.0", m["jsonrpc"])
		assert.NotContains(t, m, "session_id")
		assert.NotContains(t, m, "event")
	}
	assert.Len(t, sink.records(t), 2)
}

// Without an explicit writer the trail goes to the process stderr.
func TestAuditDefaultsToStderr(t *testing.T) {
	s, err := New(Options{WorkDir: writeFixture(t, twoEnvConfig, nil)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	assert.Same(t, os.Stderr, s.auditOut)
}
