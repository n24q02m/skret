package local

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newAuditTestProvider builds a local provider over a temp secrets file in
// the "dev" environment (the default audit trail is the sibling log).
func newAuditTestProvider(t *testing.T) (*Provider, string) {
	t.Helper()
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "dev.yaml")
	cfg := &config.ResolvedConfig{
		EnvName:  "dev",
		Provider: "local",
		File:     cfgFile,
	}
	p, err := New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p.(*Provider), filepath.Join(dir, AuditFileName)
}

func TestAudit_SetAppendsNamesOnly(t *testing.T) {
	p, logPath := newAuditTestProvider(t)

	require.NoError(t, p.Set(context.Background(), "DB_URL", "postgres://super-secret-value", provider.SecretMeta{}))

	raw, err := os.ReadFile(logPath)
	require.NoError(t, err)
	text := string(raw)
	assert.NotContains(t, text, "super-secret-value", "audit trail must never contain values")

	var entries []AuditEntry
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		var e AuditEntry
		require.NoErrorf(t, json.Unmarshal([]byte(line), &e), "line is not JSONL: %q", line)
		entries = append(entries, e)
	}
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, AuditOpSet, e.Op)
	assert.Equal(t, []string{"DB_URL"}, e.KeyNames)
	assert.Equal(t, "dev", e.Env)
	assert.NotEmpty(t, e.Actor)
	ts, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC(), ts, time.Minute)
}

func TestAudit_SetContextStampRecordsRotate(t *testing.T) {
	p, logPath := newAuditTestProvider(t)

	ctx := WithAuditOp(context.Background(), AuditOpRotate)
	require.NoError(t, p.Set(ctx, "API_KEY", "v1", provider.SecretMeta{}))

	entries, skipped, err := ReadAuditLog(logPath)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Zero(t, skipped)
	assert.Equal(t, AuditOpRotate, entries[0].Op)
	assert.Equal(t, []string{"API_KEY"}, entries[0].KeyNames)
}

func TestAudit_DeleteAppendsOp(t *testing.T) {
	p, logPath := newAuditTestProvider(t)

	require.NoError(t, p.Set(context.Background(), "TOKEN", "v1", provider.SecretMeta{}))
	require.NoError(t, p.Delete(context.Background(), "TOKEN"))

	entries, _, err := ReadAuditLog(logPath)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, AuditOpSet, entries[0].Op)
	assert.Equal(t, AuditOpDelete, entries[1].Op)
	assert.Equal(t, []string{"TOKEN"}, entries[1].KeyNames)
}

func TestAudit_FileCreatedWithOwnerOnlyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits not enforced on Windows")
	}
	p, logPath := newAuditTestProvider(t)

	require.NoError(t, p.Set(context.Background(), "K", "v", provider.SecretMeta{}))

	info, err := os.Stat(logPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "audit log must be owner-only")
}

func TestAudit_RotationKeepsSingleBackup(t *testing.T) {
	p, logPath := newAuditTestProvider(t)

	// Seed the active log past the rotation threshold.
	big := strings.Repeat("x", AuditRotateBytes)
	require.NoError(t, os.WriteFile(logPath, []byte(big), 0o600))

	require.NoError(t, p.Set(context.Background(), "K2", "v2", provider.SecretMeta{}))

	backup, err := os.ReadFile(logPath + ".1")
	require.NoError(t, err)
	assert.Equal(t, AuditRotateBytes, len(backup), "previous log becomes the single backup")

	active, err := os.ReadFile(logPath)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(active), "\n"), "\n")
	require.Len(t, lines, 1, "active log restarts fresh after rotation")
	assert.Contains(t, lines[0], `"K2"`)
}

func TestAudit_RotationOnlyAtThreshold(t *testing.T) {
	p, logPath := newAuditTestProvider(t)

	require.NoError(t, p.Set(context.Background(), "A", "v", provider.SecretMeta{}))
	require.NoError(t, p.Set(context.Background(), "B", "v", provider.SecretMeta{}))

	_, err := os.Stat(logPath + ".1")
	assert.True(t, os.IsNotExist(err), "no backup below the threshold")
	entries, _, err := ReadAuditLog(logPath)
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

func TestReadAuditLog_SkipsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, AuditFileName)
	content := "{\"timestamp\":\"2026-01-01T00:00:00Z\",\"op\":\"set\",\"key_names\":[\"A\"],\"env\":\"dev\",\"actor\":\"u\"}\n" +
		"not-json-at-all\n" +
		"\n" +
		"{\"timestamp\":\"2026-01-02T00:00:00Z\",\"op\":\"delete\",\"key_names\":[\"B\"],\"env\":\"dev\",\"actor\":\"u\"}\n" +
		"{\"timestamp\":\"2026-01-03T00:00:00Z\",\"op\":\"\",\"key_names\":[],\"env\":\"dev\",\"actor\":\"u\"}\n"
	require.NoError(t, os.WriteFile(logPath, []byte(content), 0o600))

	entries, skipped, err := ReadAuditLog(logPath)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, 2, skipped, "malformed JSON and op-less lines are skipped; blank lines are silently ignored")
	assert.Equal(t, "set", entries[0].Op)
	assert.Equal(t, "delete", entries[1].Op)
}

func TestReadAuditLog_MissingFile(t *testing.T) {
	_, _, err := ReadAuditLog(filepath.Join(t.TempDir(), AuditFileName))
	require.Error(t, err)
	assert.True(t, os.IsNotExist(err))
}

func TestAuditActor_EnvOverrideWins(t *testing.T) {
	t.Setenv("SKRET_ACTOR", "deploy-bot")
	assert.Equal(t, "deploy-bot", auditActor())
}

func TestSanitizeActor(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"deploy-bot", "deploy-bot"},
		{`MACHINE\alice`, "alice"},
		{"HOST\nuser", "HOST-user"}, // stray whitespace joined; no DOMAIN separator
		{"ci bot", "ci-bot"},
		{"  ", "unknown"},
		{"", "unknown"},
	} {
		assert.Equal(t, tc.want, sanitizeActor(tc.in), "input %q", tc.in)
	}
}

func TestAuditLogPathFor_OverrideAndDefault(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.ResolvedConfig{File: filepath.Join(dir, "dev.yaml")}
	assert.Equal(t, filepath.Join(dir, AuditFileName), AuditLogPathFor(cfg))

	cfg.AuditLog = "/tmp/custom-audit.log"
	assert.Equal(t, "/tmp/custom-audit.log", AuditLogPathFor(cfg))
}

func TestAudit_AppendErrorFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	// The audit path IS a directory: opening it for append always fails, on
	// every platform, even though the secrets file itself is writable.
	blocked := filepath.Join(dir, "blocked")
	require.NoError(t, os.Mkdir(blocked, 0o700))

	cfgFile := filepath.Join(dir, "dev.yaml")
	p := &Provider{filePath: cfgFile, envName: "dev", auditPath: blocked}

	err := p.Set(context.Background(), "K", "v", provider.SecretMeta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit")
}
