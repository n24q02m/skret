package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/syncer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeCLISignedStateManifest(t *testing.T, root string, extraFiles map[string]string) (manifestPath, publicKeyHex string, manifest *syncer.StateManifest) {
	t.Helper()
	for name, contents := range extraFiles {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	}

	now := time.Now().UTC().Truncate(time.Second)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	manifest, err = syncer.BuildStateManifest(root, "operator", "hub", "cli-migration-nonce", now.Add(10*time.Minute), privateKey, now)
	require.NoError(t, err)

	manifestPath = filepath.Join(t.TempDir(), "state-manifest.json")
	encoded, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, encoded, 0o600))
	return manifestPath, hex.EncodeToString(publicKey), manifest
}

func executeStateMigrationCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errOut.String(), err
}

func TestRootCmd_RegistersSyncStateMigrate(t *testing.T) {
	root := NewRootCmd()
	parent, _, err := root.Find([]string{"sync-state"})
	require.NoError(t, err)
	require.NotNil(t, parent)
	assert.Equal(t, "sync-state", parent.Name())
	child, _, err := parent.Find([]string{"migrate"})
	require.NoError(t, err)
	require.NotNil(t, child)
	assert.Equal(t, "migrate", child.Name())
	for _, flag := range []string{"to", "state-manifest", "journal", "state", "public-key", "role", "audience", "operation-id", "execute", "remote-execute", "executor-url", "operator-session", "signing-key", "format"} {
		assert.NotNil(t, child.Flags().Lookup(flag), "missing flag %q", flag)
	}
}

func TestSyncStateMigrate_DryRunVerifiesWithoutMutationAndJSONIsValueFree(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	original := []byte(`{"schema_version":1,"metadata":"opaque-cli-state-value","hashes":{"key":"opaque-hash"}}`)
	require.NoError(t, os.WriteFile(statePath, original, 0o600))
	manifestPath, publicKeyHex, manifest := writeCLISignedStateManifest(t, root, map[string]string{"state.json": string(original)})
	journalPath := filepath.Join(root, "migration.journal.json")

	stdout, stderr, err := executeStateMigrationCLI(t,
		"sync-state", "migrate", "--to", "v2",
		"--state-manifest", manifestPath,
		"--journal", journalPath,
		"--state", statePath,
		"--public-key", publicKeyHex,
		"--role", manifest.Role,
		"--audience", manifest.Audience,
		"--operation-id", "op-cli-dry-run",
		"--format", "json",
	)
	require.NoError(t, err)
	assert.Empty(t, stderr)
	assert.Equal(t, original, mustReadCLIFile(t, statePath))
	assert.NoFileExists(t, statePath+".v1")
	assert.NoFileExists(t, journalPath)
	assert.NotContains(t, stdout, "opaque-cli-state-value")
	assert.NotContains(t, stdout, "opaque-hash")
	assert.Contains(t, stdout, `"phase": "verified"`)
	assert.Contains(t, stdout, `"source_hash"`)
	assert.Contains(t, stdout, `"manifest_digest"`)
}

func TestSyncStateMigrate_ExecuteMigratesAndPrintsMetadataOnly(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	original := []byte(`{"schema_version":1,"metadata":"opaque-cli-execute-value"}`)
	require.NoError(t, os.WriteFile(statePath, original, 0o600))
	manifestPath, publicKeyHex, manifest := writeCLISignedStateManifest(t, root, map[string]string{"state.json": string(original)})
	journalPath := filepath.Join(root, "migration.journal.json")

	stdout, stderr, err := executeStateMigrationCLI(t,
		"sync-state", "migrate", "--to", "v2",
		"--state-manifest", manifestPath,
		"--journal", journalPath,
		"--state", statePath,
		"--public-key", publicKeyHex,
		"--role", manifest.Role,
		"--audience", manifest.Audience,
		"--operation-id", "op-cli-execute",
		"--execute",
		"--format", "json",
	)
	require.NoError(t, err)
	assert.Empty(t, stderr)
	assert.NotContains(t, stdout, "opaque-cli-execute-value")
	assert.NotContains(t, stdout, "schema_version")
	assert.Contains(t, stdout, `"phase": "committed"`)
	assert.Contains(t, stdout, `"backup_path"`)
	assert.Contains(t, stdout, `"desired_hash"`)

	backup := mustReadCLIFile(t, statePath+".v1")
	assert.Equal(t, original, backup)
	var migrated map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(mustReadCLIFile(t, statePath), &migrated))
	assert.Equal(t, json.RawMessage(`2`), migrated["schema_version"])
	assert.FileExists(t, journalPath)
	journalBytes := mustReadCLIFile(t, journalPath)
	assert.NotContains(t, string(journalBytes), "opaque-cli-execute-value")
}

func TestSyncStateMigrate_ManifestMismatchFailsBeforeMutation(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	original := []byte(`{"schema_version":1,"metadata":"opaque-cli-mismatch-value"}`)
	require.NoError(t, os.WriteFile(statePath, original, 0o600))
	manifestPath, publicKeyHex, manifest := writeCLISignedStateManifest(t, root, map[string]string{"state.json": string(original)})
	require.NoError(t, os.WriteFile(statePath, []byte(`{"schema_version":1,"metadata":"changed-after-signing"}`), 0o600))
	journalPath := filepath.Join(root, "migration.journal.json")

	_, _, err := executeStateMigrationCLI(t,
		"sync-state", "migrate", "--to", "v2",
		"--state-manifest", manifestPath,
		"--journal", journalPath,
		"--state", statePath,
		"--public-key", publicKeyHex,
		"--role", manifest.Role,
		"--audience", manifest.Audience,
		"--operation-id", "op-cli-mismatch",
		"--execute",
	)
	require.Error(t, err)
	assert.Equal(t, []byte(`{"schema_version":1,"metadata":"changed-after-signing"}`), mustReadCLIFile(t, statePath))
	assert.NoFileExists(t, statePath+".v1")
	assert.NoFileExists(t, journalPath)
	assert.NotContains(t, err.Error(), "changed-after-signing")
}

func TestSyncStateMigrate_ResolvesOnlyExactManifestRow(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	original := []byte(`{"schema_version":1}`)
	require.NoError(t, os.WriteFile(statePath, original, 0o600))
	manifestPath, publicKeyHex, manifest := writeCLISignedStateManifest(t, root, map[string]string{
		"state.json": originalString(original),
		"other.json": "metadata-only fixture",
	})
	journalPath := filepath.Join(root, "migration.journal.json")

	_, _, err := executeStateMigrationCLI(t,
		"sync-state", "migrate", "--to", "v2",
		"--state-manifest", manifestPath,
		"--journal", journalPath,
		"--state", root+string(filepath.Separator)+".."+string(filepath.Separator)+filepath.Base(root)+string(filepath.Separator)+"state.json",
		"--public-key", publicKeyHex,
		"--role", manifest.Role,
		"--audience", manifest.Audience,
		"--operation-id", "op-cli-traversal",
	)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "traversal")
	assert.NoFileExists(t, statePath+".v1")
	assert.NoFileExists(t, journalPath)

	_, _, err = executeStateMigrationCLI(t,
		"sync-state", "migrate", "--to", "v2",
		"--state-manifest", manifestPath,
		"--journal", journalPath,
		"--public-key", publicKeyHex,
		"--role", manifest.Role,
		"--audience", manifest.Audience,
	)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "exactly one")
}

func TestSyncStateMigrate_AcceptsPublicKeyFilesAndInfersSingleStateRow(t *testing.T) {
	root := t.TempDir()
	original := []byte(`{"schema_version":1}`)
	statePath := filepath.Join(root, "state.json")
	require.NoError(t, os.WriteFile(statePath, original, 0o600))
	manifestPath, publicKeyHex, manifest := writeCLISignedStateManifest(t, root, map[string]string{"state.json": originalString(original)})
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	require.NoError(t, err)

	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "raw", data: publicKeyBytes},
		{name: "hex", data: []byte(publicKeyHex)},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "operator-key")
			require.NoError(t, os.WriteFile(keyPath, test.data, 0o600))
			journalPath := filepath.Join(t.TempDir(), "migration.journal.json")
			stdout, stderr, err := executeStateMigrationCLI(t,
				"sync-state", "migrate", "--to", "v2",
				"--state-manifest", manifestPath,
				"--journal", journalPath,
				"--public-key", keyPath,
				"--role", manifest.Role,
				"--audience", manifest.Audience,
				"--format", "json",
			)
			require.NoError(t, err)
			assert.Empty(t, stderr)
			assert.Contains(t, stdout, `"phase": "verified"`)
			assert.Equal(t, original, mustReadCLIFile(t, statePath))
			assert.NoFileExists(t, journalPath)
		})
	}
}

func TestSyncStateMigrate_ExecuteReplaysCommittedOperationIdempotently(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	original := []byte(`{"schema_version":1,"metadata":"opaque-cli-idempotent-value"}`)
	require.NoError(t, os.WriteFile(statePath, original, 0o600))
	manifestPath, publicKeyHex, manifest := writeCLISignedStateManifest(t, root, map[string]string{"state.json": originalString(original)})
	journalPath := filepath.Join(root, "migration.journal.json")
	args := []string{
		"sync-state", "migrate", "--to", "v2",
		"--state-manifest", manifestPath,
		"--journal", journalPath,
		"--state", statePath,
		"--public-key", publicKeyHex,
		"--role", manifest.Role,
		"--audience", manifest.Audience,
		"--operation-id", "op-cli-idempotent",
		"--execute", "--format", "json",
	}
	first, _, err := executeStateMigrationCLI(t, args...)
	require.NoError(t, err)
	second, _, err := executeStateMigrationCLI(t, args...)
	require.NoError(t, err)
	assert.Equal(t, first, second)
	assert.Equal(t, original, mustReadCLIFile(t, statePath+".v1"))
	assert.NotContains(t, second, "opaque-cli-idempotent-value")
}

func TestSyncStateMigrate_RejectsInvalidFlagsAndMissingExecutionIdentity(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	original := []byte(`{"schema_version":1}`)
	require.NoError(t, os.WriteFile(statePath, original, 0o600))
	manifestPath, publicKeyHex, manifest := writeCLISignedStateManifest(t, root, map[string]string{"state.json": originalString(original)})
	journalPath := filepath.Join(root, "migration.journal.json")

	base := []string{
		"sync-state", "migrate", "--state-manifest", manifestPath, "--journal", journalPath,
		"--state", statePath, "--public-key", publicKeyHex, "--role", manifest.Role,
		"--audience", manifest.Audience, "--operation-id", "op-cli-invalid", "--execute",
	}
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "unsupported target", args: append(append([]string{}, base...), "--to", "v3"), want: "v2"},
		{name: "invalid format", args: append(append([]string{}, base...), "--to", "v2", "--format", "yaml"), want: "format"},
		{name: "missing state manifest", args: []string{"sync-state", "migrate", "--to", "v2", "--journal", journalPath, "--state", statePath, "--public-key", publicKeyHex, "--role", manifest.Role, "--audience", manifest.Audience, "--operation-id", "op-cli-missing-manifest", "--execute"}, want: "state-manifest"},
		{name: "missing journal", args: []string{"sync-state", "migrate", "--to", "v2", "--state-manifest", manifestPath, "--state", statePath, "--public-key", publicKeyHex, "--role", manifest.Role, "--audience", manifest.Audience, "--operation-id", "op-cli-missing-journal", "--execute"}, want: "journal"},
		{name: "missing public key", args: []string{"sync-state", "migrate", "--to", "v2", "--state-manifest", manifestPath, "--journal", journalPath, "--state", statePath, "--role", manifest.Role, "--audience", manifest.Audience, "--operation-id", "op-cli-missing-key", "--execute"}, want: "public-key"},
		{name: "missing role", args: []string{"sync-state", "migrate", "--to", "v2", "--state-manifest", manifestPath, "--journal", journalPath, "--state", statePath, "--public-key", publicKeyHex, "--audience", manifest.Audience, "--operation-id", "op-cli-missing-role", "--execute"}, want: "role"},
		{name: "missing audience", args: []string{"sync-state", "migrate", "--to", "v2", "--state-manifest", manifestPath, "--journal", journalPath, "--state", statePath, "--public-key", publicKeyHex, "--role", manifest.Role, "--operation-id", "op-cli-missing-audience", "--execute"}, want: "audience"},
		{name: "invalid operation id", args: []string{"sync-state", "migrate", "--to", "v2", "--state-manifest", manifestPath, "--journal", journalPath, "--state", statePath, "--public-key", publicKeyHex, "--role", manifest.Role, "--audience", manifest.Audience, "--operation-id", "not valid", "--execute"}, want: "operation"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := executeStateMigrationCLI(t, test.args...)
			require.Error(t, err)
			assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(test.want))
		})
	}
}

func TestReadCLIStateMigrationPrivateKey_AcceptsRawAndHexFiles(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "raw", data: privateKey},
		{name: "hex", data: []byte(hex.EncodeToString(privateKey))},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "operator-signing-key")
			require.NoError(t, os.WriteFile(keyPath, test.data, 0o600))

			got, err := readCLIStateMigrationPrivateKey(keyPath)
			require.NoError(t, err)
			assert.Equal(t, ed25519.PrivateKey(privateKey), got)
		})
	}
}

func TestSyncStateMigrate_RemoteExecuteSubmitsSignedMetadataOnlyRequestWithoutMutation(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	original := []byte(`{"schema_version":1,"metadata":"opaque-cli-remote-value"}`)
	require.NoError(t, os.WriteFile(statePath, original, 0o600))
	manifestPath, publicKeyHex, manifest := writeCLISignedStateManifest(t, root, map[string]string{"state.json": string(original)})
	journalPath := filepath.Join(root, "migration.journal.json")
	remotePublicKey, remotePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signingKeyPath := filepath.Join(t.TempDir(), "operator-signing-key")
	require.NoError(t, os.WriteFile(signingKeyPath, remotePrivateKey, 0o600))

	var received syncer.ExecutorEnvelope
	var receivedBody map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/operator/executor-envelope", r.URL.Path)
		assert.Equal(t, "session=opaque-operator-session", r.Header.Get("Cookie"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(&received))
		require.NoError(t, json.Unmarshal(received.Body, &receivedBody))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accepted":true,"response_secret":"opaque-remote-response-value"}`))
	}))
	defer server.Close()

	stdout, stderr, err := executeStateMigrationCLI(t,
		"sync-state", "migrate", "--to", "v2",
		"--state-manifest", manifestPath,
		"--journal", journalPath,
		"--state", statePath,
		"--public-key", publicKeyHex,
		"--role", manifest.Role,
		"--audience", manifest.Audience,
		"--operation-id", "op-cli-remote",
		"--executor-url", server.URL,
		"--operator-session", "session=opaque-operator-session",
		"--signing-key", signingKeyPath,
		"--remote-execute",
		"--format", "json",
	)
	require.NoError(t, err)
	assert.Empty(t, stderr)
	assert.NotContains(t, stdout, "opaque-cli-remote-value")
	assert.NotContains(t, stdout, "opaque-remote-response-value")
	assert.Contains(t, stdout, `"phase": "submitted"`)
	assert.Contains(t, stdout, `"response_hash"`)
	assert.Contains(t, stdout, `"response_size"`)
	assert.Equal(t, original, mustReadCLIFile(t, statePath))
	assert.NoFileExists(t, statePath+".v1")
	assert.NoFileExists(t, journalPath)

	require.NoError(t, syncer.VerifySignedEnvelope(&received, remotePublicKey, time.Now().UTC()))
	assert.Equal(t, manifest.Role, received.Role)
	assert.Equal(t, manifest.Audience, received.Audience)
	assert.Equal(t, mustCLIStateMigrationManifestDigest(t, manifest), received.ManifestDigest)
	assert.NotEmpty(t, received.Nonce)
	assert.False(t, received.ExpiresAt.IsZero())
	require.Len(t, receivedBody, 7)
	statePathJSON, err := json.Marshal(statePath)
	require.NoError(t, err)
	journalPathJSON, err := json.Marshal(journalPath)
	require.NoError(t, err)
	assert.Equal(t, `"op-cli-remote"`, string(receivedBody["operation_id"]))
	assert.Equal(t, string(statePathJSON), string(receivedBody["state_path"]))
	assert.Equal(t, string(journalPathJSON), string(receivedBody["journal_path"]))
	assert.Equal(t, `"`+mustCLIStateMigrationManifestDigest(t, manifest)+`"`, string(receivedBody["manifest_digest"]))
	assert.Equal(t, `"v2"`, string(receivedBody["target"]))
	assert.Equal(t, `"`+manifest.Files[0].SHA256+`"`, string(receivedBody["source_hash"]))
	assert.Equal(t, strconv.FormatInt(int64(len(original)), 10), string(receivedBody["source_size"]))
	assert.NotContains(t, string(received.Body), "opaque-cli-remote-value")
	assert.NotContains(t, string(received.Body), "schema_version")
}

func TestSyncStateMigrate_RemoteModeRequiresAuthenticatedInputsAndRejectsLocalExecute(t *testing.T) {
	t.Setenv("SKRET_OPERATOR_SESSION_COOKIE", "")
	base := []string{"sync-state", "migrate", "--remote-execute", "--state-manifest", "manifest.json", "--journal", "journal.json", "--public-key", "public.key", "--state", "state.json", "--role", "operator", "--audience", "hub", "--operation-id", "op-cli-auth", "--executor-url", "http://127.0.0.1:1", "--operator-session", "session=opaque", "--signing-key", "private.key"}
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "missing executor url", args: removeCLIStateMigrationFlag(base, "--executor-url"), want: "executor-url"},
		{name: "missing operator session", args: removeCLIStateMigrationFlag(base, "--operator-session"), want: "operator-session"},
		{name: "missing signing key", args: removeCLIStateMigrationFlag(base, "--signing-key"), want: "signing-key"},
		{name: "missing role", args: removeCLIStateMigrationFlag(base, "--role"), want: "role"},
		{name: "missing audience", args: removeCLIStateMigrationFlag(base, "--audience"), want: "audience"},
		{name: "missing operation id", args: removeCLIStateMigrationFlag(base, "--operation-id"), want: "operation-id"},
		{name: "remote and local execute", args: append(append([]string{}, base...), "--execute"), want: "mutually exclusive"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := executeStateMigrationCLI(t, test.args...)
			require.Error(t, err)
			assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(test.want))
		})
	}
}

func TestSyncStateMigrate_RemoteErrorIsValueFreeAndDoesNotMutateLocalState(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	original := []byte(`{"schema_version":1,"metadata":"opaque-cli-remote-error-value"}`)
	require.NoError(t, os.WriteFile(statePath, original, 0o600))
	manifestPath, publicKeyHex, manifest := writeCLISignedStateManifest(t, root, map[string]string{"state.json": string(original)})
	journalPath := filepath.Join(root, "migration.journal.json")
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signingKeyPath := filepath.Join(t.TempDir(), "operator-signing-key")
	require.NoError(t, os.WriteFile(signingKeyPath, []byte(hex.EncodeToString(privateKey)), 0o600))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "opaque-remote-error-value", http.StatusBadGateway)
	}))
	defer server.Close()

	stdout, stderr, err := executeStateMigrationCLI(t,
		"sync-state", "migrate", "--to", "v2",
		"--state-manifest", manifestPath,
		"--journal", journalPath,
		"--state", statePath,
		"--public-key", publicKeyHex,
		"--role", manifest.Role,
		"--audience", manifest.Audience,
		"--operation-id", "op-cli-remote-error",
		"--executor-url", server.URL,
		"--operator-session", "session=opaque-operator-session",
		"--signing-key", signingKeyPath,
		"--remote-execute",
		"--format", "json",
	)
	require.Error(t, err)
	assert.Empty(t, stdout)
	assert.NotContains(t, stderr, "opaque-remote-error-value")
	assert.NotContains(t, err.Error(), "opaque-remote-error-value")
	assert.NotContains(t, err.Error(), "opaque-cli-remote-error-value")
	assert.Equal(t, original, mustReadCLIFile(t, statePath))
	assert.NoFileExists(t, statePath+".v1")
	assert.NoFileExists(t, journalPath)
}

func TestSyncStateMigrate_RemoteModeUsesOperatorSessionEnvironmentFallback(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	original := []byte(`{"schema_version":1}`)
	require.NoError(t, os.WriteFile(statePath, original, 0o600))
	manifestPath, publicKeyHex, manifest := writeCLISignedStateManifest(t, root, map[string]string{"state.json": string(original)})
	journalPath := filepath.Join(root, "migration.journal.json")
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signingKeyPath := filepath.Join(t.TempDir(), "operator-signing-key")
	require.NoError(t, os.WriteFile(signingKeyPath, privateKey, 0o600))
	var gotCookie string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	defer server.Close()
	t.Setenv("SKRET_OPERATOR_SESSION_COOKIE", "session=opaque-env-session")

	_, _, err = executeStateMigrationCLI(t,
		"sync-state", "migrate", "--state-manifest", manifestPath,
		"--journal", journalPath, "--state", statePath, "--public-key", publicKeyHex,
		"--role", manifest.Role, "--audience", manifest.Audience, "--operation-id", "op-cli-env",
		"--executor-url", server.URL, "--signing-key", signingKeyPath, "--remote-execute",
	)
	require.NoError(t, err)
	assert.Equal(t, "session=opaque-env-session", gotCookie)
	assert.Equal(t, original, mustReadCLIFile(t, statePath))
	assert.NoFileExists(t, statePath+".v1")
	assert.NoFileExists(t, journalPath)
}

func mustCLIStateMigrationManifestDigest(t *testing.T, manifest *syncer.StateManifest) string {
	t.Helper()
	digest, err := cliStateMigrationManifestDigest(manifest)
	require.NoError(t, err)
	return digest
}

func removeCLIStateMigrationFlag(args []string, flag string) []string {
	result := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			i++
			continue
		}
		result = append(result, args[i])
	}
	return result
}

func originalString(value []byte) string {
	return string(value)
}

func mustReadCLIFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}
