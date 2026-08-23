package syncer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stateMigrationFixture(t *testing.T) (root, statePath, journalPath string, manifest *StateManifest, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, now time.Time, original []byte) {
	t.Helper()
	now = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	root = t.TempDir()
	statePath = filepath.Join(root, "state.json")
	journalPath = filepath.Join(root, "state-migration.journal.json")
	original = []byte(`{"schema_version":1,"target":"synthetic","metadata":"sensitive-state-value","hashes":{"key":"opaque-hash"}}`)
	require.NoError(t, os.WriteFile(statePath, original, 0o600))
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	manifest, err = BuildStateManifest(root, "operator", "hub", "nonce-state-migration", now.Add(5*time.Minute), privateKey, now)
	require.NoError(t, err)
	return
}

func stateMigrationManifestDigest(t *testing.T, manifest *StateManifest) string {
	t.Helper()
	canonical, err := manifest.CanonicalSigningBytes()
	require.NoError(t, err)
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func stateMigrationHash(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func stateMigrationV2Bytes(t *testing.T, original []byte, manifestDigest string) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(original, &object))
	object["schema_version"] = json.RawMessage(`2`)
	digestJSON, err := json.Marshal(manifestDigest)
	require.NoError(t, err)
	object["manifest_digest"] = digestJSON
	encoded, err := json.Marshal(object)
	require.NoError(t, err)
	return encoded
}

func writeStateMigrationJournal(t *testing.T, path string, journal StateMigrationJournal) {
	t.Helper()
	data, err := json.Marshal(journal)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func readStateMigrationJournal(t *testing.T, path string) StateMigrationJournal {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var journal StateMigrationJournal
	require.NoError(t, json.Unmarshal(data, &journal))
	return journal
}

func TestStateMigration_SuccessPreservesV1AndJournalsValueFreeCommit(t *testing.T) {
	root, statePath, journalPath, manifest, publicKey, _, now, original := stateMigrationFixture(t)
	operationID := "op-state-migration-success"

	require.NoError(t, MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", operationID, now))

	backup, err := os.ReadFile(statePath + ".v1")
	require.NoError(t, err)
	assert.Equal(t, original, backup, "the original v1 bytes must remain preserved")
	migrated, err := os.ReadFile(statePath)
	require.NoError(t, err)
	var object map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(migrated, &object))
	assert.Equal(t, json.RawMessage(`2`), object["schema_version"])
	digestJSON, err := json.Marshal(stateMigrationManifestDigest(t, manifest))
	require.NoError(t, err)
	assert.Equal(t, json.RawMessage(digestJSON), object["manifest_digest"])
	assert.Equal(t, json.RawMessage(`"sensitive-state-value"`), object["metadata"])

	journal := readStateMigrationJournal(t, journalPath)
	assert.Equal(t, StateMigrationJournalVersion, journal.Version)
	assert.Equal(t, operationID, journal.OperationID)
	assert.Equal(t, StateMigrationPhaseCommitted, journal.Phase)
	assert.Equal(t, statePath, journal.SourcePath)
	assert.Equal(t, statePath+".v1", journal.BackupPath)
	assert.Equal(t, journalPath, journal.JournalPath)
	journalBytes, err := os.ReadFile(journalPath)
	require.NoError(t, err)
	assert.NotContains(t, string(journalBytes), "sensitive-state-value")
	assert.NotContains(t, string(journalBytes), "opaque-hash")
	assert.Empty(t, migrationTempFiles(t, filepath.Dir(statePath)))
	assert.Equal(t, root, filepath.Dir(statePath))
}

func TestStateMigration_VerifiesManifestBeforeMutation(t *testing.T) {
	_, statePath, journalPath, manifest, publicKey, _, now, _ := stateMigrationFixture(t)
	const changedValue = "sensitive-tampered-value"
	require.NoError(t, os.WriteFile(statePath, []byte(`{"schema_version":1,"metadata":"`+changedValue+`"}`), 0o600))

	err := MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-state-migration-mismatch", now)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), changedValue)
	assert.NotContains(t, err.Error(), "sensitive-state-value")
	assert.FileExists(t, statePath)
	assert.NoFileExists(t, statePath+".v1")
	assert.NoFileExists(t, journalPath)
	assert.Empty(t, migrationTempFiles(t, filepath.Dir(statePath)))
}

func TestStateMigration_RejectsNonV1ObjectsAndTrailingData(t *testing.T) {
	_, statePath, journalPath, manifest, publicKey, _, now, _ := stateMigrationFixture(t)
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{name: "array", body: []byte(`[]`)},
		{name: "schema v2", body: []byte(`{"schema_version":2}`)},
		{name: "trailing data", body: []byte(`{"schema_version":1} trailing-sensitive-value`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(statePath, tc.body, 0o600))
			err := MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-state-migration-invalid-v1", now)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "trailing-sensitive-value")
			assert.NoFileExists(t, statePath+".v1")
			assert.NoFileExists(t, journalPath)
			assert.Empty(t, migrationTempFiles(t, filepath.Dir(statePath)))
		})
	}
}

func TestStateMigration_RecoversPreparedByRestoringV1(t *testing.T) {
	_, statePath, journalPath, manifest, _, _, now, original := stateMigrationFixture(t)
	manifestDigest := stateMigrationManifestDigest(t, manifest)
	tempPath := filepath.Join(filepath.Dir(statePath), ".state.json.v2-crash")
	desired := stateMigrationV2Bytes(t, original, manifestDigest)
	require.NoError(t, os.WriteFile(tempPath, desired, 0o600))
	writeStateMigrationJournal(t, journalPath, StateMigrationJournal{
		Version:        StateMigrationJournalVersion,
		OperationID:    "op-state-migration-prepared",
		ManifestDigest: manifestDigest,
		SourcePath:     statePath,
		BackupPath:     statePath + ".v1",
		TempPath:       tempPath,
		JournalPath:    journalPath,
		SourceHash:     stateMigrationHash(original),
		SourceSize:     int64(len(original)),
		DesiredHash:    stateMigrationHash(desired),
		DesiredSize:    int64(len(desired)),
		Phase:          StateMigrationPhasePrepared,
		CreatedAt:      now,
		UpdatedAt:      now,
	})

	err := RecoverStateMigration(journalPath, now.Add(time.Minute))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrStateMigrationNeedsReconciliation))
	recovered, readErr := os.ReadFile(statePath)
	require.NoError(t, readErr)
	assert.Equal(t, original, recovered)
	assert.NoFileExists(t, tempPath)
	assert.NoFileExists(t, statePath+".v1")
	assert.Equal(t, StateMigrationPhaseNeedsReconciliation, readStateMigrationJournal(t, journalPath).Phase)
}

func TestStateMigration_RecoversBackupRenamedByCompletingV2Commit(t *testing.T) {
	_, statePath, journalPath, manifest, _, _, now, original := stateMigrationFixture(t)
	manifestDigest := stateMigrationManifestDigest(t, manifest)
	desired := stateMigrationV2Bytes(t, original, manifestDigest)
	backupPath := statePath + ".v1"
	tempPath := filepath.Join(filepath.Dir(statePath), ".state.json.v2-crash")
	require.NoError(t, os.Rename(statePath, backupPath))
	require.NoError(t, os.WriteFile(tempPath, desired, 0o600))
	writeStateMigrationJournal(t, journalPath, StateMigrationJournal{
		Version:        StateMigrationJournalVersion,
		OperationID:    "op-state-migration-backup",
		ManifestDigest: manifestDigest,
		SourcePath:     statePath,
		BackupPath:     backupPath,
		TempPath:       tempPath,
		JournalPath:    journalPath,
		SourceHash:     stateMigrationHash(original),
		SourceSize:     int64(len(original)),
		DesiredHash:    stateMigrationHash(desired),
		DesiredSize:    int64(len(desired)),
		Phase:          StateMigrationPhaseBackupRenamed,
		CreatedAt:      now,
		UpdatedAt:      now,
	})

	require.NoError(t, RecoverStateMigration(journalPath, now.Add(time.Minute)))
	migrated, err := os.ReadFile(statePath)
	require.NoError(t, err)
	assert.Equal(t, desired, migrated)
	preserved, err := os.ReadFile(backupPath)
	require.NoError(t, err)
	assert.Equal(t, original, preserved)
	assert.NoFileExists(t, tempPath)
	assert.Equal(t, StateMigrationPhaseCommitted, readStateMigrationJournal(t, journalPath).Phase)
}
func TestStateMigration_PreparedRecoveryRestoresSourceWithoutDeletingBackup(t *testing.T) {
	_, statePath, journalPath, manifest, _, _, now, original := stateMigrationFixture(t)
	manifestDigest := stateMigrationManifestDigest(t, manifest)
	desired := stateMigrationV2Bytes(t, original, manifestDigest)
	backupPath := statePath + ".v1"
	tempPath := filepath.Join(filepath.Dir(statePath), ".state.json.v2-crash")
	require.NoError(t, os.Rename(statePath, backupPath))
	require.NoError(t, os.WriteFile(tempPath, desired, 0o600))
	writeStateMigrationJournal(t, journalPath, StateMigrationJournal{
		Version:        StateMigrationJournalVersion,
		OperationID:    "op-state-migration-prepared-backup",
		ManifestDigest: manifestDigest,
		SourcePath:     statePath,
		BackupPath:     backupPath,
		TempPath:       tempPath,
		JournalPath:    journalPath,
		SourceHash:     stateMigrationHash(original),
		SourceSize:     int64(len(original)),
		DesiredHash:    stateMigrationHash(desired),
		DesiredSize:    int64(len(desired)),
		Phase:          StateMigrationPhasePrepared,
		CreatedAt:      now,
		UpdatedAt:      now,
	})

	err := RecoverStateMigration(journalPath, now.Add(time.Minute))
	require.ErrorIs(t, err, ErrStateMigrationNeedsReconciliation)
	assert.Equal(t, original, mustReadFile(t, statePath))
	assert.Equal(t, original, mustReadFile(t, backupPath))
	assert.NoFileExists(t, tempPath)
}

func TestStateMigration_IdempotentForCommittedOperationAndRejectsDifferentOperation(t *testing.T) {
	_, statePath, journalPath, manifest, publicKey, _, now, original := stateMigrationFixture(t)
	operationID := "op-state-migration-idempotent"
	require.NoError(t, MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", operationID, now))
	before, err := os.ReadFile(statePath)
	require.NoError(t, err)
	require.NoError(t, MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", operationID, now.Add(time.Minute)))
	after, err := os.ReadFile(statePath)
	require.NoError(t, err)
	assert.Equal(t, before, after)

	err = MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-state-migration-other", now.Add(time.Minute))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "sensitive-state-value")
	assert.Equal(t, before, mustReadFile(t, statePath))
	assert.Equal(t, original, mustReadFile(t, statePath+".v1"))
}

func TestStateMigration_RecoveryAmbiguityFailsClosedWithoutOverwritingFiles(t *testing.T) {
	_, statePath, journalPath, manifest, _, _, now, original := stateMigrationFixture(t)
	manifestDigest := stateMigrationManifestDigest(t, manifest)
	desired := stateMigrationV2Bytes(t, original, manifestDigest)
	backupPath := statePath + ".v1"
	tempPath := filepath.Join(filepath.Dir(statePath), ".state.json.v2-crash")
	require.NoError(t, os.WriteFile(backupPath, original, 0o600))
	require.NoError(t, os.WriteFile(tempPath, desired, 0o600))
	writeStateMigrationJournal(t, journalPath, StateMigrationJournal{
		Version:        StateMigrationJournalVersion,
		OperationID:    "op-state-migration-ambiguous",
		ManifestDigest: manifestDigest,
		SourcePath:     statePath,
		BackupPath:     backupPath,
		TempPath:       tempPath,
		JournalPath:    journalPath,
		SourceHash:     stateMigrationHash(original),
		SourceSize:     int64(len(original)),
		DesiredHash:    stateMigrationHash(desired),
		DesiredSize:    int64(len(desired)),
		Phase:          StateMigrationPhaseBackupRenamed,
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	beforeSource := mustReadFile(t, statePath)
	beforeBackup := mustReadFile(t, backupPath)
	beforeTemp := mustReadFile(t, tempPath)

	err := RecoverStateMigration(journalPath, now.Add(time.Minute))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrStateMigrationNeedsReconciliation)
	assert.Equal(t, beforeSource, mustReadFile(t, statePath))
	assert.Equal(t, beforeBackup, mustReadFile(t, backupPath))
	assert.Equal(t, beforeTemp, mustReadFile(t, tempPath))
	assert.Equal(t, StateMigrationPhaseNeedsReconciliation, readStateMigrationJournal(t, journalPath).Phase)
}

func TestStateMigration_RejectsTraversalAndInvalidJournalWithoutMutation(t *testing.T) {
	_, statePath, journalPath, manifest, _, _, now, original := stateMigrationFixture(t)
	manifestDigest := stateMigrationManifestDigest(t, manifest)
	badJournal := StateMigrationJournal{
		Version:        StateMigrationJournalVersion,
		OperationID:    "op-state-migration-traversal",
		ManifestDigest: manifestDigest,
		SourcePath:     statePath,
		BackupPath:     statePath + ".v1",
		TempPath:       filepath.Join(filepath.Dir(statePath), "..", "outside.tmp"),
		JournalPath:    journalPath,
		SourceHash:     stateMigrationHash(original),
		SourceSize:     int64(len(original)),
		DesiredHash:    strings.Repeat("a", 64),
		DesiredSize:    1,

		Phase:          StateMigrationPhasePrepared,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	writeStateMigrationJournal(t, journalPath, badJournal)

	err := RecoverStateMigration(journalPath, now.Add(time.Minute))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "sensitive-state-value")
	assert.Equal(t, original, mustReadFile(t, statePath))
	assert.NoFileExists(t, statePath+".v1")
	assert.Equal(t, StateMigrationPhasePrepared, readStateMigrationJournal(t, journalPath).Phase)
}
func TestStateMigration_RejectsInvalidJournalSchemaAndHashWithoutMutation(t *testing.T) {
	_, statePath, journalPath, _, _, _, now, original := stateMigrationFixture(t)
	require.NoError(t, os.WriteFile(journalPath, []byte(`{"version":2}`), 0o600))

	err := RecoverStateMigration(journalPath, now.Add(time.Minute))
	require.ErrorIs(t, err, ErrStateMigrationInvalidJournal)
	assert.Equal(t, original, mustReadFile(t, statePath))
	assert.NoFileExists(t, statePath+".v1")
}
func TestStateMigration_PostBackupJournalFailureRetainsTempForRecovery(t *testing.T) {
	_, statePath, journalPath, manifest, publicKey, _, now, original := stateMigrationFixture(t)
	originalPersist := stateMigrationPersistJournal
	defer func() { stateMigrationPersistJournal = originalPersist }()
	var calls int
	stateMigrationPersistJournal = func(journal *StateMigrationJournal) error {
		calls++
		if calls == 2 {
			return errors.New("synthetic journal persistence failure")
		}
		return persistMigrationJournal(journal)
	}

	err := MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-state-migration-post-backup-failure", now)
	require.Error(t, err)
	assert.FileExists(t, statePath+".v1")
	assert.NoFileExists(t, statePath)
	tempFiles := migrationTempFiles(t, filepath.Dir(statePath))
	require.Len(t, tempFiles, 1, "the v2 temp must remain recoverable after backup rename")
	tempPath := filepath.Join(filepath.Dir(statePath), tempFiles[0])
	assert.Equal(t, stateMigrationV2Bytes(t, original, stateMigrationManifestDigest(t, manifest)), mustReadFile(t, tempPath))

	stateMigrationPersistJournal = originalPersist
	err = RecoverStateMigration(journalPath, now.Add(time.Minute))
	require.ErrorIs(t, err, ErrStateMigrationNeedsReconciliation)
	assert.Equal(t, original, mustReadFile(t, statePath))
	assert.Equal(t, original, mustReadFile(t, statePath+".v1"))
	assert.NoFileExists(t, tempPath)
}
func TestStateMigration_TempRenameFailureRetainsTempForRecovery(t *testing.T) {
	_, statePath, journalPath, manifest, publicKey, _, now, original := stateMigrationFixture(t)
	originalPersist := stateMigrationPersistJournal
	defer func() { stateMigrationPersistJournal = originalPersist }()
	var calls int
	stateMigrationPersistJournal = func(journal *StateMigrationJournal) error {
		calls++
		if calls == 2 {
			require.NoError(t, os.Mkdir(statePath, 0o700))
		}
		return persistMigrationJournal(journal)
	}

	err := MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-state-migration-temp-failure", now)
	require.Error(t, err)
	assert.DirExists(t, statePath)
	assert.Equal(t, original, mustReadFile(t, statePath+".v1"))
	tempFiles := migrationTempFiles(t, filepath.Dir(statePath))
	require.Len(t, tempFiles, 1, "the v2 temp must remain after a failed temp rename")
	tempPath := filepath.Join(filepath.Dir(statePath), tempFiles[0])

	stateMigrationPersistJournal = originalPersist
	err = RecoverStateMigration(journalPath, now.Add(time.Minute))
	require.Error(t, err)
	assert.FileExists(t, tempPath)
	require.NoError(t, os.RemoveAll(statePath))
	require.NoError(t, RecoverStateMigration(journalPath, now.Add(2*time.Minute)))
	assert.Equal(t, stateMigrationV2Bytes(t, original, stateMigrationManifestDigest(t, manifest)), mustReadFile(t, statePath))
	assert.Equal(t, original, mustReadFile(t, statePath+".v1"))
	assert.NoFileExists(t, tempPath)
}

func TestStateMigration_SecuresPermissiveV1Backup(t *testing.T) {
	_, statePath, journalPath, manifest, publicKey, _, now, _ := stateMigrationFixture(t)
	require.NoError(t, os.Chmod(statePath, 0o644))
	require.NoError(t, MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-state-migration-mode", now))
	if runtime.GOOS != "windows" {
		info, err := os.Stat(statePath + ".v1")
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		info, err = os.Stat(statePath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestStateMigration_RecoverySecuresRestoredBackup(t *testing.T) {
	_, statePath, journalPath, manifest, _, _, now, original := stateMigrationFixture(t)
	manifestDigest := stateMigrationManifestDigest(t, manifest)
	desired := stateMigrationV2Bytes(t, original, manifestDigest)
	backupPath := statePath + ".v1"
	tempPath := filepath.Join(filepath.Dir(statePath), ".state.json.v2-crash")
	require.NoError(t, os.Rename(statePath, backupPath))
	require.NoError(t, os.Chmod(backupPath, 0o644))
	require.NoError(t, os.WriteFile(tempPath, desired, 0o600))
	writeStateMigrationJournal(t, journalPath, StateMigrationJournal{
		Version:        StateMigrationJournalVersion,
		OperationID:    "op-state-migration-restore-mode",
		ManifestDigest: manifestDigest,
		SourcePath:     statePath,
		BackupPath:     backupPath,
		TempPath:       tempPath,
		JournalPath:    journalPath,
		SourceHash:     stateMigrationHash(original),
		SourceSize:     int64(len(original)),
		DesiredHash:    stateMigrationHash(desired),
		DesiredSize:    int64(len(desired)),
		Phase:          StateMigrationPhasePrepared,
		CreatedAt:      now,
		UpdatedAt:      now,
	})

	err := RecoverStateMigration(journalPath, now.Add(time.Minute))
	require.ErrorIs(t, err, ErrStateMigrationNeedsReconciliation)
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(backupPath)
		require.NoError(t, statErr)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		info, statErr = os.Stat(statePath)
		require.NoError(t, statErr)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func migrationTempFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var matches []string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".v2-") || strings.Contains(entry.Name(), ".tmp-") {
			matches = append(matches, entry.Name())
		}
	}
	return matches
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}
