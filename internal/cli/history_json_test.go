package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// renderHistory is exercised directly (not through the full command tree)
// because the only provider available to CLI-level tests, local, does not
// implement GetHistory at all (see TestHistoryCmd_NotSupported) -- there is
// no way to reach a non-empty history result end-to-end without a real (or
// heavily mocked) AWS SSM client, which is out of scope for this change.
func TestRenderHistory_JSONFormat_MasksByDefault(t *testing.T) {
	history := []*provider.Secret{
		{
			Key: "K", Value: "supersecretvalue", Version: 2,
			Meta: provider.SecretMeta{CreatedBy: "alice", UpdatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
		},
		{Key: "K", Value: "firstvalue", Version: 1},
	}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	require.NoError(t, renderHistory(cmd, history, "K", false, "json"))

	var got []historyEntry
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Len(t, got, len(history), "json array length must match the table row count")

	assert.Equal(t, int64(2), got[0].Version)
	assert.NotEqual(t, "supersecretvalue", got[0].Value, "masked by default, same as the table")
	assert.NotContains(t, buf.String(), "supersecretvalue")
	assert.Equal(t, "alice", got[0].Author)
	assert.Equal(t, "2026-01-02T03:04:05Z", got[0].UpdatedAt)

	assert.Empty(t, got[1].Author, "author omitted when CreatedBy is empty")
	assert.Empty(t, got[1].UpdatedAt, "updated_at omitted when the timestamp is zero")
}

func TestRenderHistory_JSONFormat_VerboseRevealsValue(t *testing.T) {
	history := []*provider.Secret{{Key: "K", Value: "supersecretvalue", Version: 1}}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	require.NoError(t, renderHistory(cmd, history, "K", true, "json"))

	var got []historyEntry
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, "supersecretvalue", got[0].Value)
}

func TestRenderHistory_JSONFormat_EmptyHistory(t *testing.T) {
	var buf, errBuf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetErr(&errBuf)

	require.NoError(t, renderHistory(cmd, nil, "K", false, "json"))
	assert.JSONEq(t, "[]", buf.String(), "empty history is an empty array, not null, in json format")
	assert.Contains(t, errBuf.String(), "No history found")
}

func TestRenderHistory_TableFormatUnchanged(t *testing.T) {
	history := []*provider.Secret{{Key: "K", Value: "v", Version: 1}}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	require.NoError(t, renderHistory(cmd, history, "K", false, "table"))
	// tabwriter pads columns with spaces once flushed, so the literal '\t'
	// bytes never reach buf -- match on the column names instead, the same
	// way the pre-existing TestRenderHistory_WithEntries does.
	out := buf.String()
	assert.Contains(t, out, "VERSION")
	assert.Contains(t, out, "VALUE")
	assert.Contains(t, out, "UPDATED AT")
	assert.Contains(t, out, "AUTHOR")
}

// TestHistoryCmd_JSONFlag_NotSupportedStillErrors confirms --format json is a
// recognized flag on `history` and does not swallow or alter the provider's
// existing ExitProviderError when the provider (local, here) doesn't
// implement GetHistory.
func TestHistoryCmd_JSONFlag_NotSupportedStillErrors(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(dir+"/.skret.yaml", []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./secrets.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(dir+"/secrets.yaml", []byte(`
version: "1"
secrets:
  KEY: "value"
`), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	t.Setenv("SKRET_EXPERIMENTAL", "1")

	cmd := newHistoryCmd(&GlobalOpts{})
	cmd.SetArgs([]string{"KEY", "--format", "json"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not support this operation")
}
