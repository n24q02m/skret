package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/provider/local"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runRootCmd invokes the root CLI with args, returning stdout/stderr/err.
func runRootCmd(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

// runAudit invokes `skret audit` with args, returning stdout/stderr/err.
func runAudit(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	return runRootCmd(t, append([]string{"audit"}, args...)...)
}

// auditEntry is the decoded --format json row (loose fields so missing
// optionals don't fail decoding).
type auditEntry struct {
	Timestamp string   `json:"timestamp"`
	Op        string   `json:"op"`
	KeyNames  []string `json:"key_names"`
	Env       string   `json:"env"`
	Actor     string   `json:"actor"`
}

// auditLogOf returns the default trail path for the writeLocalTemplateConfig
// layout (dev.yaml sibling).
func auditLogOf(dir string) string {
	return filepath.Join(dir, local.AuditFileName)
}

// seedAudit writes a handcrafted trail so filters have known history.
func seedAudit(t *testing.T, dir string, lines ...string) {
	t.Helper()
	require.NoError(t, os.WriteFile(auditLogOf(dir), []byte(strings.Join(lines, "\n")+"\n"), 0o600))
}

func auditLine(ts, op, key string) string {
	return fmt.Sprintf(`{"timestamp":%q,"op":%q,"key_names":[%q],"env":"dev","actor":"tester"}`, ts, op, key)
}

func TestAuditCmd_Local_LogsMutationsAndRenders(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	chdirTmp(t, dir)
	t.Setenv("SKRET_ACTOR", "ci-bot")

	_, _, err := runRootCmd(t, "set", "DB_URL", "postgres://fresh-value")
	require.NoError(t, err)
	_, _, err = runRootCmd(t, "delete", "TOKEN", "--force")
	require.NoError(t, err)

	// The trail itself never contains a secret value.
	raw, err := os.ReadFile(auditLogOf(dir))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "postgres://fresh-value")
	assert.NotContains(t, string(raw), "tok123")

	stdout, stderr, err := runAudit(t, "--format", "json")
	require.NoError(t, err)
	assert.Empty(t, stderr)
	var entries []auditEntry
	require.NoError(t, json.Unmarshal([]byte(stdout), &entries))
	require.Len(t, entries, 2)
	assert.Equal(t, "set", entries[0].Op)
	assert.Equal(t, []string{"DB_URL"}, entries[0].KeyNames)
	assert.Equal(t, "dev", entries[0].Env)
	assert.Equal(t, "ci-bot", entries[0].Actor, "SKRET_ACTOR is the actor")
	assert.Equal(t, "delete", entries[1].Op)

	table, _, err := runAudit(t)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(table, "TIME"), "table header present")
	assert.Equal(t, []string{"OP ENV KEYS ACTOR", "set dev DB_URL ci-bot", "delete dev TOKEN ci-bot"}, auditTableRows(t, table))
}

func TestAuditCmd_RotateRecordedAsRotate(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	chdirTmp(t, dir)

	_, _, err := runRootCmd(t, "rotate", "TOKEN", "--yes")
	require.NoError(t, err)

	entries := auditJSON(t)
	require.Len(t, entries, 1)
	assert.Equal(t, "rotate", entries[0].Op)
	assert.Equal(t, []string{"TOKEN"}, entries[0].KeyNames)
}

func TestAuditCmd_Filters(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	chdirTmp(t, dir)
	seedAudit(t, dir,
		auditLine("2020-01-01T00:00:00Z", "set", "OLD_KEY"),
		auditLine("2026-09-18T10:00:00Z", "set", "DB_URL"),
		auditLine("2026-09-19T12:00:00Z", "rotate", "DB_URL"),
		auditLine("2026-09-19T13:00:00Z", "delete", "TOKEN"),
	)

	// --key keeps only matching entries, oldest first.
	entries := auditJSON(t, "--key", "DB_URL")
	require.Len(t, entries, 2)
	assert.Equal(t, "set", entries[0].Op)
	assert.Equal(t, "rotate", entries[1].Op)

	// --since drops older entries.
	entries = auditJSON(t, "--since", "2026-09-19T00:00:00Z")
	require.Len(t, entries, 2)
	assert.Equal(t, "rotate", entries[0].Op)
	assert.Equal(t, "delete", entries[1].Op)

	// --since accepts durations too (clock-safe: the hand-seeded 2020
	// entry is outside any live --since window, so only its absence and
	// parseability are asserted).
	table, _, err := runAudit(t, "--since", "24h", "--format", "json")
	require.NoError(t, err)
	var durEntries []auditEntry
	require.NoError(t, json.Unmarshal([]byte(table), &durEntries))
	for _, e := range durEntries {
		assert.NotEqual(t, "OLD_KEY", e.KeyNames[0], "2020 entry must be outside any live --since window")
	}

	// --limit keeps the most recent N, chronological output.
	entries = auditJSON(t, "--limit", "2")
	require.Len(t, entries, 2)
	assert.Equal(t, "rotate", entries[0].Op)
	assert.Equal(t, "delete", entries[1].Op)

	// Combined.
	entries = auditJSON(t, "--key", "DB_URL", "--limit", "1")
	require.Len(t, entries, 1)
	assert.Equal(t, "rotate", entries[0].Op)

	// Table honors filters too.
	table, _, err = runAudit(t, "--key", "TOKEN")
	require.NoError(t, err)
	assert.Equal(t, []string{"OP ENV KEYS ACTOR", "delete dev TOKEN tester"}, auditTableRows(t, table))
}

func TestAuditCmd_EmptyTrail(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	chdirTmp(t, dir)

	stdout, stderr, err := runAudit(t)
	require.NoError(t, err)
	assert.Empty(t, stdout, "no data: stdout stays empty")
	assert.Contains(t, stderr, "No audit entries")

	stdout, _, err = runAudit(t, "--format", "json")
	require.NoError(t, err)
	assert.Equal(t, "[]\n", stdout, "json renders an empty array")
}

func TestAuditCmd_MalformedLinesWarn(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	chdirTmp(t, dir)
	seedAudit(t, dir,
		auditLine("2026-09-19T12:00:00Z", "set", "DB_URL"),
		"garbage-line",
	)

	_, stderr, err := runAudit(t)
	require.NoError(t, err)
	assert.Contains(t, stderr, "skipped 1 malformed audit line")
}

func TestAuditCmd_ValidationErrors(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	chdirTmp(t, dir)

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--format", "yaml"}, "unknown --format"},
		{[]string{"--limit", "-1"}, "--limit must be >= 0"},
		{[]string{"--since", "nonsense"}, "--since"},
	} {
		_, _, err := runAudit(t, tc.args...)
		require.Error(t, err, "args: %v", tc.args)
		var se *skret.Error
		require.True(t, errors.As(err, &se), "args: %v", tc.args)
		assert.Equal(t, skret.ExitValidationError, se.Code, "args: %v", tc.args)
		assert.Contains(t, err.Error(), tc.want)
	}
}

func TestAuditCmd_UnknownProviderRejected(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	chdirTmp(t, dir)

	_, _, err := runAudit(t, "--provider", "vault")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no skret-managed audit trail")
}

func TestAuditCmd_OverrideAuditLogPath(t *testing.T) {
	dir := t.TempDir()
	must := func(name, content string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	must(".skret.yaml", "version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: dev.yaml\n    audit_log: trails/audit-dev.log\n")
	must("dev.yaml", "version: \"1\"\nsecrets:\n  K: v\n")
	chdirTmp(t, dir)

	_, _, err := runRootCmd(t, "set", "NEW_K", "value")
	require.NoError(t, err)

	entries := auditJSON(t)
	require.Len(t, entries, 1)
	assert.Equal(t, "NEW_K", entries[0].KeyNames[0])
	_, err = os.Stat(filepath.Join(dir, "trails", "audit-dev.log"))
	require.NoError(t, err, "configured audit_log path is used")
}

func TestAuditCmd_MissingConfig(t *testing.T) {
	chdirTmp(t, t.TempDir())
	_, _, err := runAudit(t)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no .skret.yaml found")
}

// --- helpers shared by the cases above ---

// auditTableRows normalizes tabwriter output to header + per-row field
// lists with the leading TIME cell dropped (timestamps are live in the
// mutation-path tests; their format is pinned by the JSON assertions).
func auditTableRows(t *testing.T, table string) []string {
	t.Helper()
	var rows []string
	for _, line := range strings.Split(strings.TrimRight(table, "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 {
			fields = fields[1:]
		}
		rows = append(rows, strings.Join(fields, " "))
	}
	return rows
}

func auditJSON(t *testing.T, args ...string) []auditEntry {
	t.Helper()
	stdout, _, err := runAudit(t, append([]string{"--format", "json"}, args...)...)
	require.NoError(t, err)
	var entries []auditEntry
	require.NoError(t, json.Unmarshal([]byte(stdout), &entries))
	return entries
}
