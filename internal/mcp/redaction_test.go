package mcp

import (
	"log"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureSlog routes the default logger (the server's stderr diagnostics)
// into a buffer for the duration of the test.
func captureSlog(t *testing.T) *auditSink {
	t.Helper()
	buf := &auditSink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// A value loaded in the session never comes back through an error, the
// audit trail or the diagnostics, even when the caller echoes it back as a
// key, tool, environment or method name.
func TestLoadedValuesNeverLeakThroughErrors(t *testing.T) {
	const value = "loaded-value-9f3a"
	logs := captureSlog(t)
	dir := writeFixture(t, twoEnvConfig, map[string]string{"API_KEY": value, "OTHER": "other-value-2"})
	s, sink := auditedServer(t, dir)

	text, isErr := toolText(t, toolCall(t, s, 2, "skret_get", `{"key":"API_KEY"}`))
	require.False(t, isErr, text)
	require.Equal(t, value, text, "successful results are never redacted")

	responses := []map[string]any{
		call(t, s, `{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"`+value+`"}}`),
		toolCall(t, s, 4, "skret_get", `{"key":"`+value+`"}`),
		toolCall(t, s, 5, value, `{}`),
		toolCall(t, s, 6, "skret_get", `{"key":"API_KEY","env":"`+value+`"}`),
		call(t, s, `{"jsonrpc":"2.0","id":7,"method":"`+value+`"}`),
		call(t, s, `{"jsonrpc":"2.0","id":8,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"`+value+`"}}}`),
	}
	for i, resp := range responses[1:] {
		assert.NotContains(t, marshalResp(t, resp), value, "response %d", i+1)
		assert.Contains(t, marshalResp(t, resp), "[REDACTED]", "response %d redacts rather than drops", i+1)
	}
	assert.NotContains(t, marshalResp(t, responses[0]), value)
	assert.NotContains(t, sink.String(), value, "audit trail")
	assert.NotContains(t, logs.String(), value, "diagnostics")
	assert.Contains(t, logs.String(), "client_protocol", "the initialize diagnostic was emitted")
}

// skret_list loads every value of the environment into the redactor, not
// only the ones a caller reads.
func TestListedValuesAreRedacted(t *testing.T) {
	dir := writeFixture(t, twoEnvConfig, map[string]string{"A_KEY": "listed-value-1"})
	s := serverFor(t, dir)
	_, isErr := toolText(t, toolCall(t, s, 2, "skret_list", `{}`))
	require.False(t, isErr)
	text, isErr := toolText(t, toolCall(t, s, 3, "skret_get", `{"key":"listed-value-1"}`))
	assert.True(t, isErr)
	assert.NotContains(t, text, "listed-value-1")
	assert.Contains(t, text, "[REDACTED]")
}

// Values a caller writes are redacted from that point on.
func TestWrittenValuesAreRedacted(t *testing.T) {
	logs := captureSlog(t)
	dir := writeFixture(t, policyConfig("  allow_write: true\n"), map[string]string{"A_KEY": "a"})
	s, sink := auditedServer(t, dir)
	for _, tc := range []struct{ tool, value string }{
		{"skret_set", "written-value-1"},
		{"skret_rotate", "rotated-value-1"},
	} {
		text, isErr := toolText(t, toolCall(t, s, 2, tc.tool, `{"key":"A_KEY","value":"`+tc.value+`","confirm":true}`))
		require.False(t, isErr, text)
		text, isErr = toolText(t, toolCall(t, s, 3, "skret_delete", `{"key":"`+tc.value+`","confirm":true}`))
		assert.True(t, isErr)
		assert.NotContains(t, text, tc.value)
		assert.NotContains(t, sink.String(), tc.value)
	}
	// a refused write still registers its value before refusing
	text, isErr := toolText(t, toolCall(t, s, 4, "skret_set", `{"key":"A_KEY","value":"unconfirmed-value-1"}`))
	require.True(t, isErr, text)
	text, _ = toolText(t, toolCall(t, s, 5, "skret_get", `{"key":"unconfirmed-value-1"}`))
	assert.NotContains(t, text, "unconfirmed-value-1")
	assert.NotContains(t, logs.String(), "written-value-1")
	assert.NotContains(t, logs.String(), "rotated-value-1")
}

// The server routes the process logger through its redactor for its
// lifetime and hands the previous logger back on Close.
func TestServerScopesRedactingLogger(t *testing.T) {
	captureSlog(t)
	before := slog.Default()
	s, err := New(Options{WorkDir: writeFixture(t, twoEnvConfig, nil), AuditWriter: &auditSink{}})
	require.NoError(t, err)
	assert.NotSame(t, before, slog.Default(), "New installs the session logger")
	require.NoError(t, s.Close())
	assert.Same(t, before, slog.Default(), "Close restores the previous logger")

	// A logger replaced after New is left alone by Close.
	s, err = New(Options{WorkDir: writeFixture(t, twoEnvConfig, nil), AuditWriter: &auditSink{}})
	require.NoError(t, err)
	other := slog.New(slog.NewTextHandler(&auditSink{}, nil))
	slog.SetDefault(other)
	require.NoError(t, s.Close())
	assert.Same(t, other, slog.Default())
}

// builtinLogger is slog's built-in default, captured before any test
// replaces it. That handler writes through the standard log package.
var builtinLogger = slog.Default()

// Servers stacked over the built-in logger and closed in reverse order must
// never link the log package to a handler that writes back through it, or
// the next diagnostic deadlocks on the log package's mutex.
func TestNestedServersKeepTheBuiltinLoggerUsable(t *testing.T) {
	prevLogger, prevOut, prevFlags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(prevLogger)
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	out := &auditSink{}
	log.SetOutput(out)
	slog.SetDefault(builtinLogger)

	dir := writeFixture(t, twoEnvConfig, nil)
	outer, err := New(Options{WorkDir: dir, AuditWriter: &auditSink{}})
	require.NoError(t, err)
	inner, err := New(Options{WorkDir: dir, AuditWriter: &auditSink{}})
	require.NoError(t, err)
	require.NoError(t, inner.Close())

	done := make(chan struct{})
	go func() {
		slog.Info("logged after the inner server closed")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("logging deadlocked after a nested Close")
	}
	require.NoError(t, outer.Close())
	assert.Same(t, builtinLogger, slog.Default())
	assert.Contains(t, out.String(), "logged after the inner server closed")
}

// Secret-shaped text is redacted by pattern even when it was never loaded.
func TestErrorTextIsPatternRedacted(t *testing.T) {
	s, sink := auditedServer(t, writeFixture(t, twoEnvConfig, map[string]string{"A": "1"}))
	resp := toolCall(t, s, 2, "skret_get", `{"key":"token=abcdef123456"}`)
	text, isErr := toolText(t, resp)
	assert.True(t, isErr)
	assert.NotContains(t, text, "abcdef123456")
	assert.Contains(t, text, "token=[REDACTED]")
	errObj := rpcErrorOf(t, toolCall(t, s, 3, "AKIAABCDEFGHIJKLMNOP", `{}`))
	require.NotNil(t, errObj)
	assert.NotContains(t, errObj["message"], "AKIAABCDEFGHIJKLMNOP")
	assert.False(t, strings.Contains(sink.String(), "abcdef123456") || strings.Contains(sink.String(), "AKIAABCDEFGHIJKLMNOP"))
}
