package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/n24q02m/skret/internal/cli"
	"github.com/n24q02m/skret/internal/notify"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupNotifyRepo seeds a local-provider repo whose .skret.yaml carries the
// given notify block (verbatim YAML) and one pre-existing secret.
func setupNotifyRepo(t *testing.T, notifyBlock string) string {
	t.Helper()
	dir := setupTestRepo(t)
	f, err := os.OpenFile(filepath.Join(dir, ".skret.yaml"), os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, err = f.WriteString(notifyBlock)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return dir
}

// capturedWebhook records POST bodies across concurrent requests.
type capturedWebhook struct {
	mu     sync.Mutex
	bodies []string
	server *httptest.Server
}

func newCapturedWebhook(t *testing.T) *capturedWebhook {
	t.Helper()
	c := &capturedWebhook{}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		c.mu.Lock()
		c.bodies = append(c.bodies, string(body))
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.server.Close)
	return c
}

func (c *capturedWebhook) bodiesSnapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.bodies...)
}

func (c *capturedWebhook) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

func TestNotify_Set_FiresWebhook_NamesOnly(t *testing.T) {
	hook := newCapturedWebhook(t)
	dir := setupNotifyRepo(t, "notify:\n  webhook_url: "+hook.server.URL+"\n")
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })

	out, err := runCLI(t, "set", "BRAND_NEW_KEY", "s3cr3t-value-42", "--format", "json")
	require.NoError(t, err)
	require.Equal(t, 1, hook.count(), "a successful set must fire exactly one webhook POST")

	var payload notify.Payload
	require.NoError(t, json.Unmarshal([]byte(hook.bodiesSnapshot()[0]), &payload))
	assert.Equal(t, "set", payload.Event)
	assert.Equal(t, []string{"BRAND_NEW_KEY"}, payload.KeyNames)
	assert.Equal(t, "dev", payload.Env)
	assert.NotContains(t, string(hook.bodiesSnapshot()[0]), "s3cr3t-value-42",
		"the webhook payload must never carry the secret value")
	assert.NotContains(t, out, "s3cr3t-value-42")
}

func TestNotify_Delete_FiresWebhook(t *testing.T) {
	hook := newCapturedWebhook(t)
	dir := setupNotifyRepo(t, "notify:\n  webhook_url: "+hook.server.URL+"\n")
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })

	_, err = runCLI(t, "delete", "API_KEY", "--force")
	require.NoError(t, err)
	require.Equal(t, 1, hook.count())

	var payload notify.Payload
	require.NoError(t, json.Unmarshal([]byte(hook.bodiesSnapshot()[0]), &payload))
	assert.Equal(t, "delete", payload.Event)
	assert.Equal(t, []string{"API_KEY"}, payload.KeyNames)
}

func TestNotify_Set_FailureWarns_MutationStillSucceeds(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // nothing listens: delivery always fails

	dir := setupNotifyRepo(t, "notify:\n  webhook_url: "+deadURL+"\n")
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })

	cmd := cli.NewRootCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"set", "WARNED_KEY", "v"})
	err = cmd.Execute()
	require.NoError(t, err, "fire-and-report: notify failure must not fail the mutation")

	assert.Contains(t, stderr.String(), "warning:")
	assert.Contains(t, stderr.String(), "--strict-notify", "warning must point at the escape hatch")

	// And the write itself landed.
	got, err := runCLI(t, "get", "WARNED_KEY", "--plain")
	require.NoError(t, err)
	assert.Equal(t, "v", got)
}

func TestNotify_Set_StrictNotifyFails_AfterDurableWrite(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	dir := setupNotifyRepo(t, "notify:\n  webhook_url: "+deadURL+"\n")
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })

	cmd := cli.NewRootCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"set", "STRICT_KEY", "v", "--strict-notify"})
	err = cmd.Execute()
	require.Error(t, err, "--strict-notify must fail the command after the webhook fails")
	assert.Equal(t, skret.ExitNetworkError, skret.ExitCode(err),
		"strict-notify failure must exit ExitNetworkError (7)")

	// The mutation itself is durable even though the command failed.
	got, err := runCLI(t, "get", "STRICT_KEY", "--plain")
	require.NoError(t, err)
	assert.Equal(t, "v", got)
}

func TestNotify_Set_EventFilter_DropsOtherEvents(t *testing.T) {
	hook := newCapturedWebhook(t)
	dir := setupNotifyRepo(t, "notify:\n  webhook_url: "+hook.server.URL+"\n  events:\n    - delete\n")
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })

	_, err = runCLI(t, "set", "FILTERED_KEY", "v")
	require.NoError(t, err)
	assert.Equal(t, 0, hook.count(), "a set must not POST when notify.events only allows delete")
}

func TestNotify_Set_NoNotifyBlock_NoWebhook(t *testing.T) {
	dir := setupTestRepo(t)
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })

	// No notify block anywhere in the config: the command must run normally
	// (the disabled path is a silent no-op, never a config error).
	_, err = runCLI(t, "set", "PLAIN_MUTATION", "v")
	require.NoError(t, err)
}

// notifySyncRepo seeds a local-provider repo with the given secrets, one
// dotenv sync target, and a notify block pointed at hookURL (the yaml.v3
// equivalents live in package cli's internal test files; this file is in
// cli_test and cannot reach them).
func notifySyncRepo(t *testing.T, secrets map[string]string, hookURL string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))

	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("version: \"1\"\nsecrets:\n")
	for _, k := range keys {
		fmt.Fprintf(&sb, "  %s: %q\n", k, secrets[k])
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte(sb.String()), 0o600))

	config := "version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: secrets.yaml\n" +
		"notify:\n  webhook_url: " + hookURL + "\n" +
		"sync:\n  targets:\n    - type: dotenv\n      file: out.env\n      no_overwrite: false\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(config), 0o644))
	return dir
}

// runNotifySync runs `skret sync` with extra args inside dir and returns the
// error (nil on success) without failing the test.
func runNotifySync(t *testing.T, dir string, args ...string) error {
	t.Helper()
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(orig) }()

	cmd := cli.NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(append([]string{"sync"}, args...))
	return cmd.Execute()
}

func TestNotify_Sync_FiresWebhook_SyncAndRotate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		extraArgs []string
		wantEvent string
	}{
		{name: "sync", extraArgs: nil, wantEvent: "sync"},
		{name: "rotate", extraArgs: []string{"--rotate"}, wantEvent: "rotate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := newCapturedWebhook(t)
			dir := notifySyncRepo(t, map[string]string{"ALPHA": "1", "BETA": "2"}, hook.server.URL)

			require.NoError(t, runNotifySync(t, dir, tc.extraArgs...))
			require.Equal(t, 1, hook.count(), "one webhook POST per completed target")

			var payload notify.Payload
			require.NoError(t, json.Unmarshal([]byte(hook.bodiesSnapshot()[0]), &payload))
			assert.Equal(t, tc.wantEvent, payload.Event)
			assert.Equal(t, "dev", payload.Env)
			assert.ElementsMatch(t, []string{"ALPHA", "BETA"}, payload.KeyNames,
				"sync payloads carry source provider key names, never values")
			assert.NotContains(t, hook.bodiesSnapshot()[0], "ALPHA=1",
				"dotenv assignment syntax must never leak into the webhook body")
		})
	}
}

func TestNotify_Sync_StrictNotifyFails(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	dir := notifySyncRepo(t, map[string]string{"ALPHA": "1"}, deadURL)

	err := runNotifySync(t, dir, "--strict-notify")
	require.Error(t, err)
	assert.Equal(t, skret.ExitNetworkError, skret.ExitCode(err))

	// Fire-and-report default still succeeds against the same dead webhook.
	err = runNotifySync(t, dir)
	require.NoError(t, err)
}
