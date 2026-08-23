package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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
	for _, flag := range []string{"to", "state-manifest", "journal", "state", "public-key", "role", "audience", "operation-id", "execute", "format"} {
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

func originalString(value []byte) string {
	return string(value)
}

func mustReadCLIFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}
