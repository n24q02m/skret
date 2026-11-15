package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/syncer"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errCovAInjected = errors.New("covA injected failure")

// covAMigrationFixture is one signed single-file state root ready for
// `sync-state migrate`.
type covAMigrationFixture struct {
	root         string
	statePath    string
	journalPath  string
	manifestPath string
	publicKeyHex string
	manifest     *syncer.StateManifest
	original     []byte
}

func covANewMigrationFixture(t *testing.T) covAMigrationFixture {
	t.Helper()
	root := resolvedCLIStateMigrationRoot(t)
	original := `{"schema_version":1,"metadata":"opaque-covA-state-value"}`
	manifestPath, publicKeyHex, manifest := writeCLISignedStateManifest(t, root, map[string]string{"state.json": original})
	return covAMigrationFixture{
		root:         root,
		statePath:    filepath.Join(root, "state.json"),
		journalPath:  filepath.Join(root, "migration.journal.json"),
		manifestPath: manifestPath,
		publicKeyHex: publicKeyHex,
		manifest:     manifest,
		original:     []byte(original),
	}
}

func (f covAMigrationFixture) args(extra ...string) []string {
	args := []string{
		"sync-state", "migrate", "--to", "v2",
		"--state-manifest", f.manifestPath,
		"--journal", f.journalPath,
		"--state", f.statePath,
		"--public-key", f.publicKeyHex,
	}
	return append(args, extra...)
}

// covAAssertUntouched proves a failed migration left no local side effects.
func (f covAMigrationFixture) covAAssertUntouched(t *testing.T) {
	t.Helper()
	assert.Equal(t, f.original, mustReadCLIFile(t, f.statePath))
	assert.NoFileExists(t, f.statePath+".v1")
	assert.NoFileExists(t, f.journalPath)
}

func TestCovA_SyncStateMigrate_RunErrorBranches(t *testing.T) {
	t.Run("remote mode rejects a missing signing key before reading the manifest", func(t *testing.T) {
		f := covANewMigrationFixture(t)
		_, _, err := executeStateMigrationCLI(t, f.args(
			"--role", "operator", "--audience", "hub",
			"--operation-id", "op-covA-remote",
			"--remote-execute",
			"--executor-url", "http://127.0.0.1:1",
			"--operator-session", "session=covA",
			"--signing-key", filepath.Join(f.root, "missing-signing-key"),
		)...)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sync-state migrate: read signing key")
		assert.Contains(t, err.Error(), "signing key must be a regular file path")
		assert.Equal(t, skret.ExitGenericError, skret.ExitCode(err))
		f.covAAssertUntouched(t)
	})

	t.Run("unreadable public key", func(t *testing.T) {
		f := covANewMigrationFixture(t)
		args := removeCLIStateMigrationFlag(f.args(), "--public-key")
		args = append(args, "--public-key", filepath.Join(f.root, "missing.pub"))
		_, _, err := executeStateMigrationCLI(t, args...)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sync-state migrate: read public key")
		assert.Contains(t, err.Error(), "public key must be Ed25519 hex or a regular file path")
		assert.Equal(t, skret.ExitGenericError, skret.ExitCode(err))
		f.covAAssertUntouched(t)
	})

	t.Run("journal path containing NUL", func(t *testing.T) {
		f := covANewMigrationFixture(t)
		args := removeCLIStateMigrationFlag(f.args(), "--journal")
		args = append(args, "--journal", filepath.Join(f.root, "bad\x00journal.json"))
		_, _, err := executeStateMigrationCLI(t, args...)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sync-state migrate: resolve journal path")
		assert.Contains(t, err.Error(), "path contains NUL")
		assert.Equal(t, skret.ExitGenericError, skret.ExitCode(err))
		f.covAAssertUntouched(t)
	})

	t.Run("dry-run with the wrong audience fails verification", func(t *testing.T) {
		f := covANewMigrationFixture(t)
		_, _, err := executeStateMigrationCLI(t, f.args("--role", "operator", "--audience", "not-hub")...)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sync-state migrate: verify state manifest")
		assert.Contains(t, err.Error(), "audience mismatch")
		assert.Equal(t, skret.ExitGenericError, skret.ExitCode(err))
		f.covAAssertUntouched(t)
	})
}

func TestCovA_SyncStateMigrate_DryRunInfersRoleAudienceTable(t *testing.T) {
	f := covANewMigrationFixture(t)

	stdout, stderr, err := executeStateMigrationCLI(t, f.args()...)
	require.NoError(t, err)
	assert.Empty(t, stderr)

	digest := mustCLIStateMigrationManifestDigest(t, f.manifest)
	want := fmt.Sprintf(
		"target: v2\nphase: verified\nstate_path: %s\njournal_path: %s\nmanifest_digest: %s\nsource_hash: %s\nsource_size: %d\n",
		f.statePath, f.journalPath, digest, cliStateMigrationHash(f.original), len(f.original),
	)
	assert.Equal(t, want, stdout)
	assert.NotContains(t, stdout, "backup_path")
	assert.NotContains(t, stdout, "desired_hash")
	assert.NotContains(t, stdout, "opaque-covA-state-value")
	f.covAAssertUntouched(t)
}

func TestCovA_SyncStateMigrate_ExecuteTableOutput(t *testing.T) {
	f := covANewMigrationFixture(t)

	stdout, stderr, err := executeStateMigrationCLI(t, f.args(
		"--role", "operator", "--audience", "hub",
		"--operation-id", "op-covA-execute-table",
		"--execute",
	)...)
	require.NoError(t, err)
	assert.Empty(t, stderr)

	journal, err := readCLIStateMigrationJournal(f.journalPath)
	require.NoError(t, err)
	assert.Equal(t, syncer.StateMigrationPhaseCommitted, journal.Phase)
	want := fmt.Sprintf(
		"target: v2\nphase: committed\nstate_path: %s\nbackup_path: %s\njournal_path: %s\nmanifest_digest: %s\nsource_hash: %s\nsource_size: %d\ndesired_hash: %s\ndesired_size: %d\n",
		journal.SourcePath, journal.BackupPath, journal.JournalPath, journal.ManifestDigest,
		journal.SourceHash, journal.SourceSize, journal.DesiredHash, journal.DesiredSize,
	)
	assert.Equal(t, want, stdout)
	assert.NotContains(t, stdout, "opaque-covA-state-value")
	assert.Equal(t, f.original, mustReadCLIFile(t, f.statePath+".v1"))
	assert.NotEmpty(t, journal.DesiredHash)
}

// covAFailingWriter fails exactly on the failAt-th Write call.
type covAFailingWriter struct {
	failAt int
	writes int
	buf    bytes.Buffer
}

func (w *covAFailingWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		return 0, errCovAInjected
	}
	return w.buf.Write(p)
}

func TestCovA_WriteMigrationResult_PropagatesWriterErrors(t *testing.T) {
	result := syncStateMigrateResult{
		Target:         "v2",
		Phase:          "submitted",
		StatePath:      "/state.json",
		BackupPath:     "/state.json.v1",
		JournalPath:    "/journal.json",
		ManifestDigest: "sha256:digest",
		SourceHash:     "source-hash",
		SourceSize:     3,
		DesiredHash:    "desired-hash",
		DesiredSize:    4,
		ResponseHash:   "response-hash",
		ResponseSize:   5,
	}
	sections := []string{
		"target: v2\nphase: submitted\nstate_path: /state.json\n",
		"backup_path: /state.json.v1\n",
		"journal_path: /journal.json\nmanifest_digest: sha256:digest\nsource_hash: source-hash\nsource_size: 3\n",
		"desired_hash: desired-hash\ndesired_size: 4\n",
		"response_hash: response-hash\nresponse_size: 5\n",
	}

	for failAt := 1; failAt <= len(sections); failAt++ {
		t.Run(fmt.Sprintf("write %d fails", failAt), func(t *testing.T) {
			writer := &covAFailingWriter{failAt: failAt}
			cmd := &cobra.Command{}
			cmd.SetOut(writer)
			err := writeCLIStateMigrationResult(cmd, result, "table")
			require.ErrorIs(t, err, errCovAInjected)
			assert.Equal(t, failAt, writer.writes, "output must stop at the first failed write")
			assert.Equal(t, strings.Join(sections[:failAt-1], ""), writer.buf.String())
		})
	}

	t.Run("all writes succeed", func(t *testing.T) {
		writer := &covAFailingWriter{}
		cmd := &cobra.Command{}
		cmd.SetOut(writer)
		require.NoError(t, writeCLIStateMigrationResult(cmd, result, "table"))
		assert.Equal(t, strings.Join(sections, ""), writer.buf.String())
	})
}

// covAManifestVariant writes a mutated copy of a real signed manifest.
func covAManifestVariant(t *testing.T, mutate func(root map[string]json.RawMessage)) string {
	t.Helper()
	f := covANewMigrationFixture(t)
	var root map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(mustReadCLIFile(t, f.manifestPath), &root))
	mutate(root)
	encoded, err := json.Marshal(root)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "variant-manifest.json")
	require.NoError(t, os.WriteFile(path, encoded, 0o600))
	return path
}

func covAWriteRawManifest(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "raw-manifest.json")
	require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))
	return path
}

func covAJSONString(t *testing.T, value string) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return encoded
}

func covASignature(t *testing.T, root map[string]json.RawMessage) string {
	t.Helper()
	var signature string
	require.NoError(t, json.Unmarshal(root["signature"], &signature))
	require.Len(t, signature, 88)
	return signature
}

func TestCovA_ReadStateManifest_RejectsMalformedWire(t *testing.T) {
	t.Run("unmodified variant is accepted", func(t *testing.T) {
		path := covAManifestVariant(t, func(map[string]json.RawMessage) {})
		manifest, data, err := readCLIStateManifestWithBytes(path)
		require.NoError(t, err)
		assert.Equal(t, mustReadCLIFile(t, path), data)
		assert.Equal(t, "operator", manifest.Role)
	})

	t.Run("missing file", func(t *testing.T) {
		_, _, err := readCLIStateManifestWithBytes(filepath.Join(t.TempDir(), "missing.json"))
		require.Error(t, err)
		assert.True(t, os.IsNotExist(err), "want not-exist error, got %v", err)
	})

	rawCases := map[string]struct {
		raw  string
		want string
	}{
		"array root":           {raw: `[]`, want: "invalid state manifest JSON"},
		"invalid token":        {raw: `{"a":}`, want: "invalid state manifest JSON"},
		"truncated object":     {raw: `{"a":1`, want: "invalid state manifest JSON"},
		"nested object root":   {raw: `{"a":{},"b":[{}]}`, want: "state manifest contains invalid JSON object keys"},
		"duplicate nested key": {raw: `{"a":{"k":1,"k":2}}`, want: "state manifest contains duplicate JSON keys"},
	}
	for name, tc := range rawCases {
		t.Run(name, func(t *testing.T) {
			_, _, err := readCLIStateManifestWithBytes(covAWriteRawManifest(t, tc.raw))
			require.Error(t, err)
			assert.Equal(t, tc.want, err.Error())
		})
	}

	mutated := map[string]struct {
		mutate func(t *testing.T, root map[string]json.RawMessage)
		want   string
	}{
		"files is a string": {
			mutate: func(_ *testing.T, root map[string]json.RawMessage) { root["files"] = json.RawMessage(`"x"`) },
			want:   "invalid state manifest JSON",
		},
		"file row is not an object": {
			mutate: func(_ *testing.T, root map[string]json.RawMessage) { root["files"] = json.RawMessage(`[1]`) },
			want:   "invalid state manifest JSON",
		},
		"null signature": {
			mutate: func(_ *testing.T, root map[string]json.RawMessage) { root["signature"] = json.RawMessage(`null`) },
			want:   "invalid state manifest JSON",
		},
		"short standard base64 signature": {
			mutate: func(t *testing.T, root map[string]json.RawMessage) {
				root["signature"] = covAJSONString(t, base64.StdEncoding.EncodeToString(make([]byte, 16)))
			},
			want: "state manifest signature is not canonical standard base64",
		},
		"signature with embedded newlines": {
			// encoding/json skips \r and \n while decoding []byte, so the
			// manifest decodes; the canonical-alphabet scan must still reject it.
			mutate: func(t *testing.T, root map[string]json.RawMessage) {
				signature := covASignature(t, root)
				root["signature"] = covAJSONString(t, signature[:80]+"AA"+"\n\n\n\n"+"==")
			},
			want: "state manifest signature is not canonical standard base64",
		},
		"signature with non-zero padding bits": {
			mutate: func(t *testing.T, root map[string]json.RawMessage) {
				const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
				signature := []byte(covASignature(t, root))
				index := strings.IndexByte(alphabet, signature[85])
				require.GreaterOrEqual(t, index, 0)
				signature[85] = alphabet[(index&0b110000)|1]
				root["signature"] = covAJSONString(t, string(signature))
			},
			want: "state manifest signature is not canonical standard base64",
		},
	}
	for name, tc := range mutated {
		t.Run(name, func(t *testing.T) {
			path := covAManifestVariant(t, func(root map[string]json.RawMessage) { tc.mutate(t, root) })
			_, _, err := readCLIStateManifestWithBytes(path)
			require.Error(t, err)
			assert.Equal(t, tc.want, err.Error())
		})
	}
}

func TestCovA_StateMigrationHelpers_MissingInputs(t *testing.T) {
	dir := t.TempDir()

	_, err := readCLIStateMigrationPrivateKey(filepath.Join(dir, "missing-private"))
	assert.EqualError(t, err, "signing key must be a regular file path")

	decoded, ok := decodeCLIStateMigrationPublicKeyHex(strings.Repeat("zz", 32))
	assert.False(t, ok, "64 non-hex characters must not decode")
	assert.Nil(t, decoded)

	_, err = readCLIStateMigrationSource(filepath.Join(dir, "missing-state.json"))
	assert.True(t, os.IsNotExist(err), "want not-exist error, got %v", err)

	_, err = readCLIStateMigrationJournal(filepath.Join(dir, "missing-journal.json"))
	assert.True(t, os.IsNotExist(err), "want not-exist error, got %v", err)

	digest, err := cliStateMigrationManifestDigest(nil)
	require.Error(t, err)
	assert.Empty(t, digest)
	assert.Contains(t, err.Error(), "missing manifest")
}

// covAOverrideSave replaces saveSyncState so only the first allow calls reach
// the real store; later calls fail. It returns a pointer to the call count.
func covAOverrideSave(t *testing.T, allow int) *int {
	t.Helper()
	original := saveSyncState
	t.Cleanup(func() { saveSyncState = original })
	calls := 0
	saveSyncState = func(state *syncer.SyncState) error {
		calls++
		if calls <= allow {
			return syncer.SaveSyncState(state)
		}
		return errCovAInjected
	}
	return &calls
}

func TestCovA_Sync_LoadConfigError(t *testing.T) {
	isolateSyncHome(t)
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte("version: [\n"), 0o600))

	err := runSyncCmdErr(t, dir, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sync: load config failed")
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	assert.NoFileExists(t, filepath.Join(dir, ".env"))
}

func TestCovA_Sync_DestinationCollision(t *testing.T) {
	isolateSyncHome(t)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"db/HOST": "db.internal", "cache/HOST": "cache.internal"})
	appendSyncTarget(t, dir, `sync:
  targets:
    - type: terraform
      file: out.tfvars
`)

	out, err := runSyncCmdCapture(t, dir, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sync: terraform")
	assert.Contains(t, err.Error(), `destination name "HOST" is produced by distinct source keys`)
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	assert.NotContains(t, out, "db.internal")
	assert.NotContains(t, err.Error(), "cache.internal")
	assert.NoFileExists(t, filepath.Join(dir, "out.tfvars"))
}

func TestCovA_Sync_LockFailure(t *testing.T) {
	isolateSyncHome(t)
	original := acquireTargetLock
	t.Cleanup(func() { acquireTargetLock = original })
	var lockedTarget, lockedID string
	acquireTargetLock = func(target, id string) (func() error, error) {
		lockedTarget, lockedID = target, id
		return nil, errCovAInjected
	}
	dir := setupSyncRepoWithSecrets(t, map[string]string{"KEY": "value"})
	withDotenvTarget(t, dir, ".env", false)

	err := runSyncCmdErr(t, dir, []string{"--skip-unchanged"})
	require.Error(t, err)
	require.ErrorIs(t, err, errCovAInjected)
	assert.Contains(t, err.Error(), "sync: lock target")
	assert.Equal(t, skret.ExitGenericError, skret.ExitCode(err))
	assert.Equal(t, "dotenv", lockedTarget)
	assert.Equal(t, ".env", lockedID)
	assert.NoFileExists(t, filepath.Join(dir, ".env"))
}

func TestCovA_Sync_SaveRecoveredStateFailure(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(fmt.Sprintf(`version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: secrets.yaml
sync:
  targets:
    - type: cloudflare
      account: account
      worker: worker
      base_url: %s
`, server.URL)), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte("version: \"1\"\nsecrets:\n  A: alpha\n"), 0o600))

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("CLOUDFLARE_API_TOKEN", "token")
	started := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	stateID := cloudflareWorkerStateID(server.URL)
	require.NoError(t, syncer.SaveSyncState(&syncer.SyncState{
		Target:      "cloudflare",
		ID:          stateID,
		OperationID: "op-covA-recover",
		Phase:       syncer.OperationPhasePending,
		StartedAt:   &started,
		Hashes:      map[string]string{"A": keyedHash("A", "alpha")},
		Outcomes: map[string]syncer.KeyOutcome{
			"A": {Status: syncer.OutcomeSucceeded, OperationID: "op-covA-recover", UpdatedAt: started},
		},
	}))
	calls := covAOverrideSave(t, 0)

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"sync"})
	err = cmd.Execute()
	require.Error(t, err)
	require.ErrorIs(t, err, errCovAInjected)
	assert.Contains(t, err.Error(), "sync: save recovered state")
	assert.Equal(t, skret.ExitGenericError, skret.ExitCode(err))
	assert.Equal(t, 1, *calls)
	assert.Equal(t, 0, requests, "recovery must not call the provider")

	persisted, err := syncer.LoadSyncState("cloudflare", stateID)
	require.NoError(t, err)
	assert.Equal(t, syncer.OperationPhasePending, persisted.Phase, "failed recovery save must leave the journal pending")
	assert.Nil(t, persisted.CompletedAt)
}

func TestCovA_Sync_JournalFailureAfterSyncFailure(t *testing.T) {
	isolateSyncHome(t)
	// Two keys sharing the last path segment make the dotenv write fail
	// deterministically before any file is opened.
	dir := setupSyncRepoWithSecrets(t, map[string]string{"db/HOST": "db.internal", "cache/HOST": "cache.internal"})
	withDotenvTarget(t, dir, ".env", false)
	calls := covAOverrideSave(t, 1)

	err := runSyncCmdErr(t, dir, []string{"--skip-unchanged"})
	require.Error(t, err)
	require.ErrorIs(t, err, errCovAInjected)
	assert.Contains(t, err.Error(), "sync failed for dotenv; state journal failed")
	assert.Equal(t, skret.ExitGenericError, skret.ExitCode(err))
	assert.Equal(t, 2, *calls, "begin save succeeds, reconciliation save fails")
	assert.NotContains(t, err.Error(), "db.internal")
	assert.NoFileExists(t, filepath.Join(dir, ".env"))

	persisted, err := syncer.LoadSyncState("dotenv", ".env")
	require.NoError(t, err)
	assert.NotEmpty(t, persisted.OperationID)
	assert.Equal(t, syncer.OperationPhasePending, persisted.Phase)
}

func TestCovA_Sync_SaveAfterSuccessFailure(t *testing.T) {
	isolateSyncHome(t)
	dir := setupSyncRepoWithSecrets(t, map[string]string{"KEY": "value"})
	withDotenvTarget(t, dir, ".env", false)
	calls := covAOverrideSave(t, 1)

	out, err := runSyncCmdCapture(t, dir, []string{"--skip-unchanged"})
	require.Error(t, err)
	require.ErrorIs(t, err, errCovAInjected)
	assert.Contains(t, err.Error(), "sync: save state failed")
	assert.Equal(t, skret.ExitGenericError, skret.ExitCode(err))
	assert.Equal(t, 2, *calls, "begin save succeeds, success save fails")
	assert.NotContains(t, out, "Synced", "success must not be reported before state is durable")
	assert.Contains(t, string(mustReadCLIFile(t, filepath.Join(dir, ".env"))), "KEY=")

	persisted, err := syncer.LoadSyncState("dotenv", ".env")
	require.NoError(t, err)
	assert.Equal(t, syncer.OperationPhasePending, persisted.Phase)
}

func TestCovA_SyncStateNeedsRecovery(t *testing.T) {
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	state := &syncer.SyncState{
		OperationID: "op-current",
		Phase:       syncer.OperationPhasePending,
		Outcomes: map[string]syncer.KeyOutcome{
			"OLD": {Status: syncer.OutcomeNeedsReconciliation, OperationID: "op-previous", UpdatedAt: now},
			"NEW": {Status: syncer.OutcomeSucceeded, OperationID: "op-current", UpdatedAt: now},
		},
	}
	assert.True(t, syncStateNeedsRecovery(state), "outcomes owned by other operations are ignored")

	state.Outcomes["SECOND"] = syncer.KeyOutcome{Status: syncer.OutcomePending, OperationID: "op-current", UpdatedAt: now}
	assert.False(t, syncStateNeedsRecovery(state), "an unacknowledged owned key blocks recovery")

	onlyForeign := &syncer.SyncState{
		OperationID: "op-current",
		Phase:       syncer.OperationPhasePending,
		Outcomes: map[string]syncer.KeyOutcome{
			"OLD": {Status: syncer.OutcomeSucceeded, OperationID: "op-previous", UpdatedAt: now},
		},
	}
	assert.False(t, syncStateNeedsRecovery(onlyForeign), "no owned keys means nothing to recover")
}

// covAPerKeySyncer is an in-memory PerKeySyncer for journal-boundary tests.
type covAPerKeySyncer struct {
	name       string
	syncKeyErr error
	synced     []string
}

func (s *covAPerKeySyncer) Name() string { return s.name }

func (s *covAPerKeySyncer) Sync(context.Context, []*provider.Secret) error { return nil }

func (s *covAPerKeySyncer) SyncKey(_ context.Context, secret *provider.Secret) error {
	if s.syncKeyErr != nil {
		return s.syncKeyErr
	}
	s.synced = append(s.synced, secret.Key)
	return nil
}

func TestCovA_SyncPerKeyOperation_JournalErrors(t *testing.T) {
	isolateSyncHome(t)
	providerErr := errors.New("covA provider rejected key")
	secrets := []*provider.Secret{{Key: "A", Value: "alpha"}}
	now := time.Now().UTC()
	begun := func(t *testing.T) *syncer.SyncState {
		t.Helper()
		state := &syncer.SyncState{Target: "covA", ID: "per-key"}
		require.NoError(t, state.BeginOperation("op-covA", secrets, now))
		return state
	}

	cases := []struct {
		name       string
		state      func(t *testing.T) *syncer.SyncState
		syncKeyErr error
		allowSaves int
		secrets    []*provider.Secret
		wantPrefix string
		wantCause  error
	}{
		{
			name:       "reconciliation record rejects a foreign operation",
			state:      func(*testing.T) *syncer.SyncState { return &syncer.SyncState{OperationID: "op-other"} },
			syncKeyErr: providerErr,
			secrets:    secrets,
			wantPrefix: "record key reconciliation: ",
			wantCause:  syncer.ErrOperationMismatch,
		},
		{
			name:       "reconciliation save fails",
			state:      begun,
			syncKeyErr: providerErr,
			secrets:    secrets,
			wantPrefix: "save key reconciliation: ",
			wantCause:  errCovAInjected,
		},
		{
			name:       "success record rejects a state without the operation",
			state:      func(*testing.T) *syncer.SyncState { return &syncer.SyncState{} },
			secrets:    secrets,
			wantPrefix: "record key success: ",
			wantCause:  syncer.ErrOperationMismatch,
		},
		{
			name:       "success save fails",
			state:      begun,
			secrets:    secrets,
			wantPrefix: "save key success: ",
			wantCause:  errCovAInjected,
		},
		{
			name:       "finalize rejects a state without the operation",
			state:      func(*testing.T) *syncer.SyncState { return &syncer.SyncState{} },
			secrets:    nil,
			wantPrefix: "finalize operation: ",
			wantCause:  syncer.ErrOperationMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := tc.state(t)
			calls := covAOverrideSave(t, tc.allowSaves)
			target := &covAPerKeySyncer{name: "covA", syncKeyErr: tc.syncKeyErr}

			err := syncPerKeyOperation(context.Background(), target, state, "op-covA", tc.secrets)
			require.Error(t, err)
			var journalErr *syncJournalError
			require.True(t, errors.As(err, &journalErr), "journal failures must be typed: %v", err)
			assert.True(t, strings.HasPrefix(err.Error(), tc.wantPrefix), err.Error())
			require.ErrorIs(t, err, tc.wantCause)
			assert.NotErrorIs(t, err, providerErr, "the journal error replaces the provider error")
			assert.LessOrEqual(t, *calls, 1)
		})
	}

	t.Run("reconciliation is journaled before the provider error is returned", func(t *testing.T) {
		state := begun(t)
		calls := covAOverrideSave(t, 1)
		target := &covAPerKeySyncer{name: "covA", syncKeyErr: providerErr}
		err := syncPerKeyOperation(context.Background(), target, state, "op-covA", secrets)
		require.ErrorIs(t, err, providerErr)
		var journalErr *syncJournalError
		assert.False(t, errors.As(err, &journalErr))
		assert.Equal(t, 1, *calls)
		assert.Equal(t, syncer.OutcomeNeedsReconciliation, state.Outcomes["A"].Status)
	})
}

func TestCovA_MutationMethodAndStateIDs(t *testing.T) {
	cloudflare := &covAPerKeySyncer{name: "cloudflare"}
	assert.Equal(t, "PATCH", mutationMethod(cloudflare, syncer.TargetConfig{Type: "cloudflare", Fields: map[string]string{"pages": "site"}}))
	assert.Equal(t, "PUT", mutationMethod(cloudflare, syncer.TargetConfig{Type: "cloudflare", Fields: map[string]string{"worker": "worker"}}))

	unknown := &covAPerKeySyncer{name: "covA-unknown"}
	assert.Empty(t, targetStateID(unknown, syncer.TargetConfig{Type: "covA-unknown"}))
	assert.Empty(t, targetStateID(&covAPerKeySyncer{name: "github"}, syncer.TargetConfig{Type: "github"}),
		"an invalid external identity must not fall back to a shared state id")

	github := &covAPerKeySyncer{name: "github"}
	assert.Empty(t, syncerStateID(github, "", ""), "an empty repo has no canonical identity")
	assert.NotEmpty(t, syncerStateID(github, "", "owner/repo"))
}

func covAFreeLoopbackAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}

func covAGet(ctx context.Context, url string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func TestCovA_PlanServer_CommandServesUntilContextCancel(t *testing.T) {
	addr := covAFreeLoopbackAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := newSyncPlanServerCmd()
	cmd.SetArgs([]string{"--listen", addr, "--max-body-bytes", "4096"})
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()

	healthz := "http://" + addr + "/healthz"
	require.Eventually(t, func() bool {
		reqCtx, reqCancel := context.WithTimeout(context.Background(), time.Second)
		defer reqCancel()
		status, err := covAGet(reqCtx, healthz)
		return err == nil && status == http.StatusOK
	}, 10*time.Second, 20*time.Millisecond)

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err, "graceful shutdown after cancel is not an error")
	case <-time.After(15 * time.Second):
		t.Fatal("plan-server did not stop after context cancel")
	}

	reqCtx, reqCancel := context.WithTimeout(context.Background(), time.Second)
	defer reqCancel()
	_, err := covAGet(reqCtx, healthz)
	assert.Error(t, err, "listener must be closed after shutdown")
}

func TestCovA_PlanServer_RequestBoundaries(t *testing.T) {
	t.Run("canceled request context is a timeout", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res := httptest.NewRecorder()
		serveSyncPlanRequest(res, httptest.NewRequestWithContext(ctx, http.MethodGet, "/healthz", nil), 1<<20)
		assert.Equal(t, http.StatusRequestTimeout, res.Code)
		assert.NotContains(t, res.Body.String(), "ok")
	})

	t.Run("body read error is a bad request", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/plan", iotest.ErrReader(errCovAInjected))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		serveSyncPlanPost(res, req, 1<<20)
		assert.Equal(t, http.StatusBadRequest, res.Code)
	})

	t.Run("unknown-length body over the limit is rejected after reading", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/plan", strings.NewReader(validPlanPayload))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = -1
		res := httptest.NewRecorder()
		serveSyncPlanPost(res, req, 16)
		assert.Equal(t, http.StatusRequestEntityTooLarge, res.Code)

		req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/plan", strings.NewReader(validPlanPayload))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = -1
		res = httptest.NewRecorder()
		serveSyncPlanPost(res, req, int64(len(validPlanPayload)))
		assert.Equal(t, http.StatusOK, res.Code, "a body exactly at the limit is accepted")
	})
}

func TestCovA_PlanServer_DuplicateScannerBoundaries(t *testing.T) {
	nestedObjects := func(depth int) string {
		return strings.Repeat(`{"a":`, depth) + "1" + strings.Repeat("}", depth)
	}
	nestedArrays := func(depth int) string {
		return `{"a":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + "}"
	}

	require.NoError(t, rejectDuplicatePlanFields([]byte(nestedObjects(maxPlanJSONDepth))))
	require.ErrorIs(t, rejectDuplicatePlanFields([]byte(nestedObjects(maxPlanJSONDepth+1))), errInvalidSyncPlan)
	require.NoError(t, rejectDuplicatePlanFields([]byte(nestedArrays(maxPlanJSONDepth-1))))
	require.ErrorIs(t, rejectDuplicatePlanFields([]byte(nestedArrays(maxPlanJSONDepth))), errInvalidSyncPlan)
	require.ErrorIs(t, rejectDuplicatePlanFields([]byte(`{"a":1 "b":2}`)), errInvalidSyncPlan)
	// An array closed by '}' stops the element loop and fails the closing token.
	require.ErrorIs(t, rejectDuplicatePlanFields([]byte(`{"a":[1}`)), errInvalidSyncPlan)
	require.ErrorIs(t, rejectDuplicatePlanFields([]byte(`{"a":["x"`)), errInvalidSyncPlan)

	decoder := json.NewDecoder(strings.NewReader(""))
	require.ErrorIs(t, scanPlanValue(decoder, json.Delim('}'), 1), errInvalidSyncPlan)
	require.ErrorIs(t, scanPlanValue(decoder, json.Delim(']'), 1), errInvalidSyncPlan)
	assert.NoError(t, scanPlanValue(decoder, "scalar", 1))
}
