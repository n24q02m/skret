package mcp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A .skret.yaml that exists but does not parse fails the server at startup
// as a config error, before any tool call can run against a guessed config.
func TestNewFailsOnMalformedConfig(t *testing.T) {
	dir := writeFixture(t, "version: [unterminated\n", nil)
	_, err := New(Options{WorkDir: dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "skret-mcp: failed to load configuration")
}

// A tool call without an env argument uses --env first, then default_env,
// then the only declared environment.
func TestDefaultEnvPrecedence(t *testing.T) {
	t.Run("--env beats default_env", func(t *testing.T) {
		dir := writeFixture(t, twoEnvConfig, nil)
		s, err := New(Options{WorkDir: dir, Env: "prod"})
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })
		_, env, err := s.clientFor("")
		require.NoError(t, err)
		assert.Equal(t, "prod", env)
	})
	t.Run("single environment without default_env", func(t *testing.T) {
		cfg := `version: "1"
environments:
  only:
    provider: local
    file: .secrets.only.yaml
`
		s := serverFor(t, writeFixture(t, cfg, nil))
		_, env, err := s.clientFor("")
		require.NoError(t, err)
		assert.Equal(t, "only", env)
	})
}

// A provider that cannot be built (here: an unparsable secrets file) is a
// tool error for that call, and the broken client is not cached, so a fixed
// file is picked up by the next call.
func TestProviderInitFailureIsToolErrorAndNotCached(t *testing.T) {
	cfg := `version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: .secrets.dev.yaml
`
	dir := writeFixture(t, cfg, nil)
	secrets := filepath.Join(dir, ".secrets.dev.yaml")
	require.NoError(t, os.WriteFile(secrets, []byte("secrets: [unterminated\n"), 0o600))
	s := serverFor(t, dir)

	text, isErr := toolText(t, toolCall(t, s, 2, "skret_get", `{"key":"K"}`))
	require.True(t, isErr, text)
	assert.Contains(t, text, `failed to initialize provider "local"`)
	assert.Empty(t, s.clients, "a failed client must not be cached")

	require.NoError(t, os.WriteFile(secrets, []byte("version: \"1\"\nsecrets:\n  K: fixed\n"), 0o600))
	text, isErr = toolText(t, toolCall(t, s, 3, "skret_get", `{"key":"K"}`))
	require.False(t, isErr, text)
	assert.Equal(t, "fixed", text)
}

// failingWriter is a client stdout that has gone away.
type failingWriter struct{ writes int }

func (f *failingWriter) Write([]byte) (int, error) {
	f.writes++
	return 0, errors.New("broken pipe")
}

// A client that closed stdout does not stop the server: every request is
// still handled and Serve ends cleanly at EOF.
func TestServeKeepsDrainingWhenStdoutFails(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, nil))
	w := &failingWriter{}
	in := `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n"
	require.NoError(t, s.Serve(strings.NewReader(in), w))
	assert.Equal(t, 2, w.writes)
}

// tools/call params that are not the documented object are a protocol
// error, not a tool result.
func TestToolsCallMalformedParamsIsProtocolError(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, nil))
	resp := call(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":5}}`)
	errObj := rpcErrorOf(t, resp)
	require.NotNil(t, errObj, "expected a protocol error: %v", resp)
	assert.InDelta(t, float64(codeInvalidParams), errObj["code"], 0)
	assert.Contains(t, errObj["message"], "invalid params")
}

// A tools/call without an arguments object runs the tool with no
// arguments, so the default environment applies.
func TestToolsCallWithoutArgumentsUsesDefaults(t *testing.T) {
	s := serverFor(t, writeFixture(t, twoEnvConfig, map[string]string{"API_KEY": devValue1}))
	resp := call(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"skret_list"}}`)
	text, isErr := toolText(t, resp)
	require.False(t, isErr, text)
	assert.Equal(t, `["API_KEY"]`, text)
}

// blockedAuditFixture is a write-enabled project whose dev audit trail
// cannot be written (its parent directory is a regular file) and whose prod
// environment is outside mcp.allowed_envs.
func blockedAuditFixture(t *testing.T) (string, *Server) {
	t.Helper()
	cfg := `version: "1"
default_env: dev
mcp:
  allow_write: true
  allowed_envs: [dev]
environments:
  dev:
    provider: local
    file: .secrets.dev.yaml
    audit_log: blocker/audit.log
  prod:
    provider: local
    file: .secrets.prod.yaml
`
	dir := writeFixture(t, cfg, map[string]string{"API_KEY": "old"})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "blocker"), []byte("not a dir"), 0o600))
	return dir, serverFor(t, dir)
}

// A list whose audit entry cannot be written fails loudly, like a get.
func TestListAuditFailureIsToolError(t *testing.T) {
	_, s := blockedAuditFixture(t)
	text, isErr := toolText(t, toolCall(t, s, 2, "skret_list", `{}`))
	assert.True(t, isErr, "an unauditable list must fail: %s", text)
	assert.Contains(t, text, "audit")
	assert.NotContains(t, text, "API_KEY", "a failed list must not return the names")
}

// Write tools enforce allowed_envs per call, report a missing argument
// before touching any environment, and surface a store failure (here the
// audit trail) as a tool error.
func TestWriteToolFailurePaths(t *testing.T) {
	tests := []struct {
		name string
		tool string
		args string
		want string
	}{
		{"set disallowed env", "skret_set", `{"key":"K","value":"v","confirm":true,"env":"prod"}`, "not permitted by mcp.allowed_envs"},
		{"delete disallowed env", "skret_delete", `{"key":"API_KEY","confirm":true,"env":"prod"}`, "not permitted by mcp.allowed_envs"},
		{"rotate disallowed env", "skret_rotate", `{"key":"API_KEY","value":"v","confirm":true,"env":"prod"}`, "not permitted by mcp.allowed_envs"},
		{"delete without key", "skret_delete", `{"confirm":true}`, "skret_delete: key or value argument missing"},
		{"rotate without value", "skret_rotate", `{"key":"API_KEY","confirm":true}`, "skret_rotate: key or value argument missing"},
		{"set store failure", "skret_set", `{"key":"NEW_KEY","value":"v","confirm":true}`, "audit"},
		{"rotate store failure", "skret_rotate", `{"key":"API_KEY","value":"rotated","confirm":true}`, "audit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, s := blockedAuditFixture(t)
			text, isErr := toolText(t, toolCall(t, s, 2, tt.tool, tt.args))
			assert.True(t, isErr, text)
			assert.Contains(t, text, tt.want)
			assert.NotContains(t, text, "rotated", "a failed write must not echo the value")
		})
	}
}
