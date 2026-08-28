package syncer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func coverageMigrationRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	return root
}

func coverageMigrationJournal(t *testing.T, statePath, journalPath, tempPath string, manifestDigest string, original, desired []byte, phase StateMigrationPhase, now time.Time) StateMigrationJournal {
	t.Helper()
	return StateMigrationJournal{
		Version:        StateMigrationJournalVersion,
		OperationID:    "op-coverage-migration",
		ManifestDigest: manifestDigest,
		SourcePath:     statePath,
		BackupPath:     statePath + ".v1",
		TempPath:       tempPath,
		JournalPath:    journalPath,
		SourceHash:     stateMigrationHash(original),
		SourceSize:     int64(len(original)),
		DesiredHash:    stateMigrationHash(desired),
		DesiredSize:    int64(len(desired)),
		Phase:          phase,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func TestStateMigration_RecoveryCommitsPreparedAndBackupRenamedInputs(t *testing.T) {
	_, statePath, journalPath, manifest, _, _, now, original := stateMigrationFixture(t)
	manifestDigest := stateMigrationManifestDigest(t, manifest)
	desired := stateMigrationV2Bytes(t, original, manifestDigest)

	t.Run("prepared journal with committed files", func(t *testing.T) {
		root := coverageMigrationRoot(t)
		source := filepath.Join(root, "state.json")
		journalPath := filepath.Join(root, "migration.journal.json")
		backup := source + ".v1"
		temp := filepath.Join(root, ".state.json.v2-temp")
		require.NoError(t, os.WriteFile(backup, original, 0o600))
		require.NoError(t, os.WriteFile(source, desired, 0o600))
		journal := coverageMigrationJournal(t, source, journalPath, temp, manifestDigest, original, desired, StateMigrationPhasePrepared, now)
		writeStateMigrationJournal(t, journalPath, journal)

		require.NoError(t, RecoverStateMigration(journalPath, now.Add(time.Minute)))
		assert.Equal(t, desired, mustReadFile(t, source))
		assert.Equal(t, original, mustReadFile(t, backup))
		assert.NoFileExists(t, temp)
		assert.Equal(t, StateMigrationPhaseCommitted, readStateMigrationJournal(t, journalPath).Phase)
	})

	t.Run("backup-renamed journal with all commit inputs", func(t *testing.T) {
		root := coverageMigrationRoot(t)
		source := filepath.Join(root, "state.json")
		journalPath := filepath.Join(root, "migration.journal.json")
		backup := source + ".v1"
		temp := filepath.Join(root, ".state.json.v2-temp")
		require.NoError(t, os.WriteFile(backup, original, 0o600))
		require.NoError(t, os.WriteFile(source, desired, 0o600))
		require.NoError(t, os.WriteFile(temp, desired, 0o600))
		journal := coverageMigrationJournal(t, source, journalPath, temp, manifestDigest, original, desired, StateMigrationPhaseBackupRenamed, now)
		writeStateMigrationJournal(t, journalPath, journal)

		require.NoError(t, RecoverStateMigration(journalPath, now.Add(time.Minute)))
		assert.Equal(t, desired, mustReadFile(t, source))
		assert.Equal(t, original, mustReadFile(t, backup))
		assert.NoFileExists(t, temp)
		assert.Equal(t, StateMigrationPhaseCommitted, readStateMigrationJournal(t, journalPath).Phase)
	})

	_ = statePath
	_ = journalPath
}

func TestStateMigration_RecoveryCommittedAndReconciliationPhasesAreTerminal(t *testing.T) {
	_, statePath, journalPath, manifest, _, _, now, original := stateMigrationFixture(t)
	manifestDigest := stateMigrationManifestDigest(t, manifest)
	desired := stateMigrationV2Bytes(t, original, manifestDigest)
	backupPath := statePath + ".v1"
	tempPath := filepath.Join(filepath.Dir(statePath), ".state.json.v2-terminal")
	require.NoError(t, os.WriteFile(statePath, desired, 0o600))
	require.NoError(t, os.WriteFile(backupPath, original, 0o600))

	t.Run("committed phase remains idempotent", func(t *testing.T) {
		journal := coverageMigrationJournal(t, statePath, journalPath, tempPath, manifestDigest, original, desired, StateMigrationPhaseCommitted, now)
		writeStateMigrationJournal(t, journalPath, journal)
		require.NoError(t, RecoverStateMigration(journalPath, now.Add(time.Minute)))
		assert.Equal(t, StateMigrationPhaseCommitted, readStateMigrationJournal(t, journalPath).Phase)
	})

	t.Run("needs reconciliation remains closed", func(t *testing.T) {
		journal := coverageMigrationJournal(t, statePath, journalPath, tempPath, manifestDigest, original, desired, StateMigrationPhaseNeedsReconciliation, now)
		writeStateMigrationJournal(t, journalPath, journal)
		err := RecoverStateMigration(journalPath, now.Add(2*time.Minute))
		require.ErrorIs(t, err, ErrStateMigrationNeedsReconciliation)
		assert.Equal(t, StateMigrationPhaseNeedsReconciliation, readStateMigrationJournal(t, journalPath).Phase)
		assert.Equal(t, desired, mustReadFile(t, statePath))
		assert.Equal(t, original, mustReadFile(t, backupPath))
	})
}

func TestStateMigration_RecoveryRetainsChangedArtifactsForReconciliation(t *testing.T) {
	_, statePath, journalPath, manifest, _, _, now, original := stateMigrationFixture(t)
	manifestDigest := stateMigrationManifestDigest(t, manifest)
	desired := stateMigrationV2Bytes(t, original, manifestDigest)
	tempPath := filepath.Join(filepath.Dir(statePath), ".state.json.v2-retained")
	require.NoError(t, os.WriteFile(tempPath, []byte("changed-retained-artifact"), 0o600))
	journal := coverageMigrationJournal(t, statePath, journalPath, tempPath, manifestDigest, original, desired, StateMigrationPhasePrepared, now)
	writeStateMigrationJournal(t, journalPath, journal)

	err := RecoverStateMigration(journalPath, now.Add(time.Minute))
	require.ErrorIs(t, err, ErrStateMigrationNeedsReconciliation)
	assert.Equal(t, original, mustReadFile(t, statePath))
	assert.Equal(t, []byte("changed-retained-artifact"), mustReadFile(t, tempPath))
	assert.NoFileExists(t, statePath+".v1")
	assert.Equal(t, StateMigrationPhaseNeedsReconciliation, readStateMigrationJournal(t, journalPath).Phase)
}

func TestStateMigration_RecoveryRejectsMalformedOrUnsafeJournals(t *testing.T) {
	root := coverageMigrationRoot(t)
	journalPath := filepath.Join(root, "migration.journal.json")
	now := time.Date(2026, 8, 24, 15, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		body []byte
	}{
		{name: "malformed json", body: []byte("{")},
		{name: "unknown field", body: []byte(`{"version":1,"unexpected":true}`)},
		{name: "trailing data", body: []byte(`{"version":1} trailing-value`)},
		{name: "invalid operation id", body: []byte(`{"version":1,"operation_id":"bad id"}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(journalPath, test.body, 0o600))
			err := RecoverStateMigration(journalPath, now)
			require.ErrorIs(t, err, ErrStateMigrationInvalidJournal)
		})
	}

	t.Run("journal directory is not accepted", func(t *testing.T) {
		directory := filepath.Join(root, "journal-directory")
		require.NoError(t, os.Mkdir(directory, 0o700))
		err := RecoverStateMigration(directory, now)
		require.ErrorIs(t, err, ErrStateMigrationInvalidJournal)
	})
}

func TestStateMigration_MigrateRejectsExistingJournalAndArtifacts(t *testing.T) {
	t.Run("existing backup", func(t *testing.T) {
		root, statePath, journalPath, _, publicKey, privateKey, now, original := stateMigrationFixture(t)
		require.NoError(t, os.WriteFile(statePath+".v1", original, 0o600))
		manifest, err := BuildStateManifest(root, "operator", "hub", "nonce-state-migration", now.Add(5*time.Minute), privateKey, now)
		require.NoError(t, err)
		err = MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-backup-exists", now)
		require.ErrorContains(t, err, "v1 backup already exists")
		assert.Equal(t, original, mustReadFile(t, statePath))
	})

	t.Run("existing journal requires recovery", func(t *testing.T) {
		_, statePath, _, manifest, publicKey, _, now, original := stateMigrationFixture(t)
		journalPath := filepath.Join(coverageMigrationRoot(t), "migration.journal.json")
		manifestDigest := stateMigrationManifestDigest(t, manifest)
		desired := stateMigrationV2Bytes(t, original, manifestDigest)
		tempPath := filepath.Join(filepath.Dir(statePath), ".state.json.v2-existing")
		journal := coverageMigrationJournal(t, statePath, journalPath, tempPath, manifestDigest, original, desired, StateMigrationPhasePrepared, now)
		writeStateMigrationJournal(t, journalPath, journal)
		err := MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", journal.OperationID, now)
		require.ErrorContains(t, err, "existing journal requires recovery")
		assert.Equal(t, original, mustReadFile(t, statePath))
	})

	t.Run("operation mismatch is rejected", func(t *testing.T) {
		_, statePath, _, manifest, publicKey, _, now, original := stateMigrationFixture(t)
		journalPath := filepath.Join(coverageMigrationRoot(t), "migration.journal.json")
		manifestDigest := stateMigrationManifestDigest(t, manifest)
		desired := stateMigrationV2Bytes(t, original, manifestDigest)
		journal := coverageMigrationJournal(t, statePath, journalPath, filepath.Join(filepath.Dir(statePath), ".temp"), manifestDigest, original, desired, StateMigrationPhasePrepared, now)
		journal.OperationID = "op-other"
		writeStateMigrationJournal(t, journalPath, journal)
		err := MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-requested", now)
		require.ErrorContains(t, err, "journal operation mismatch")
	})

	t.Run("manifest mismatch is rejected", func(t *testing.T) {
		_, statePath, _, manifest, publicKey, _, now, original := stateMigrationFixture(t)
		journalPath := filepath.Join(coverageMigrationRoot(t), "migration.journal.json")
		desired := stateMigrationV2Bytes(t, original, stateMigrationManifestDigest(t, manifest))
		journal := coverageMigrationJournal(t, statePath, journalPath, filepath.Join(filepath.Dir(statePath), ".temp"), "sha256:"+strings.Repeat("b", 64), original, desired, StateMigrationPhasePrepared, now)
		writeStateMigrationJournal(t, journalPath, journal)
		err := MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", journal.OperationID, now)
		require.ErrorContains(t, err, "journal manifest mismatch")
	})
}

func TestStateMigration_MigrateValidatesRequestBeforeMutation(t *testing.T) {
	_, statePath, journalPath, manifest, publicKey, _, now, original := stateMigrationFixture(t)

	tests := []struct {
		name        string
		statePath   string
		journalPath string
		operationID string
	}{
		{name: "invalid operation id", statePath: statePath, journalPath: journalPath, operationID: "bad operation"},
		{name: "relative state path", statePath: "relative-state.json", journalPath: journalPath, operationID: "op-relative-state"},
		{name: "relative journal path", statePath: statePath, journalPath: "relative-journal.json", operationID: "op-relative-journal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := MigrateStateFileV1ToV2(test.statePath, test.journalPath, manifest, publicKey, "operator", "hub", test.operationID, now)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "sensitive-state-value")
			assert.Equal(t, original, mustReadFile(t, statePath))
			assert.NoFileExists(t, statePath+".v1")
		})
	}

	t.Run("nil manifest fails closed", func(t *testing.T) {
		err := MigrateStateFileV1ToV2(statePath, journalPath, nil, publicKey, "operator", "hub", "op-nil-manifest", now)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "sensitive-state-value")
	})
}

func TestStateMigration_RecoveryMismatchedInputsNeverMutateUnrelatedArtifacts(t *testing.T) {
	now := time.Date(2026, 8, 24, 15, 30, 0, 0, time.UTC)
	original := []byte(`{"schema_version":1,"metadata":"original"}`)
	desired := []byte(`{"schema_version":2,"manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	manifestDigest := "sha256:" + strings.Repeat("a", 64)

	tests := []struct {
		name   string
		phase  StateMigrationPhase
		setup  func(source, backup, temp string) error
		mutate func(source, backup, temp string) error
	}{
		{
			name:  "prepared committed source changes",
			phase: StateMigrationPhasePrepared,
			setup: func(source, backup, temp string) error {
				if err := os.WriteFile(backup, original, 0o600); err != nil {
					return err
				}
				return os.WriteFile(source, desired, 0o600)
			},
			mutate: func(source, backup, temp string) error {
				return os.WriteFile(source, []byte("changed-source"), 0o600)
			},
		},
		{
			name:  "prepared rollback temp changes",
			phase: StateMigrationPhasePrepared,
			setup: func(source, backup, temp string) error {
				if err := os.WriteFile(source, original, 0o600); err != nil {
					return err
				}
				return os.WriteFile(temp, desired, 0o600)
			},
			mutate: func(source, backup, temp string) error {
				return os.WriteFile(temp, []byte("changed-temp"), 0o600)
			},
		},
		{
			name:  "prepared recovery backup changes",
			phase: StateMigrationPhasePrepared,
			setup: func(source, backup, temp string) error {
				if err := os.WriteFile(backup, original, 0o600); err != nil {
					return err
				}
				return os.WriteFile(temp, desired, 0o600)
			},
			mutate: func(source, backup, temp string) error {
				return os.WriteFile(backup, []byte("changed-backup"), 0o600)
			},
		},
		{
			name:  "backup renamed commit temp changes",
			phase: StateMigrationPhaseBackupRenamed,
			setup: func(source, backup, temp string) error {
				if err := os.WriteFile(source, desired, 0o600); err != nil {
					return err
				}
				if err := os.WriteFile(backup, original, 0o600); err != nil {
					return err
				}
				return os.WriteFile(temp, desired, 0o600)
			},
			mutate: func(source, backup, temp string) error {
				return os.WriteFile(temp, []byte("changed-temp"), 0o600)
			},
		},
		{
			name:  "backup renamed recovery temp changes",
			phase: StateMigrationPhaseBackupRenamed,
			setup: func(source, backup, temp string) error {
				if err := os.WriteFile(backup, original, 0o600); err != nil {
					return err
				}
				return os.WriteFile(temp, desired, 0o600)
			},
			mutate: func(source, backup, temp string) error {
				return os.WriteFile(temp, []byte("changed-temp"), 0o600)
			},
		},
		{
			name:  "committed backup changes",
			phase: StateMigrationPhaseCommitted,
			setup: func(source, backup, temp string) error {
				if err := os.WriteFile(source, desired, 0o600); err != nil {
					return err
				}
				return os.WriteFile(backup, original, 0o600)
			},
			mutate: func(source, backup, temp string) error {
				return os.WriteFile(backup, []byte("changed-backup"), 0o600)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := coverageMigrationRoot(t)
			source := filepath.Join(root, "state.json")
			backup := source + ".v1"
			temp := filepath.Join(root, ".state.json.v2-temp")
			journalPath := filepath.Join(root, "migration.journal.json")
			require.NoError(t, test.setup(source, backup, temp))
			journal := coverageMigrationJournal(t, source, journalPath, temp, manifestDigest, original, desired, test.phase, now)
			writeStateMigrationJournal(t, journalPath, journal)

			originalHook := stateMigrationBeforeRecoveryCommit
			defer func() { stateMigrationBeforeRecoveryCommit = originalHook }()
			stateMigrationBeforeRecoveryCommit = func(*StateMigrationJournal) error {
				return test.mutate(source, backup, temp)
			}

			err := RecoverStateMigration(journalPath, now.Add(time.Minute))
			require.ErrorIs(t, err, ErrStateMigrationNeedsReconciliation)
			assert.Equal(t, StateMigrationPhaseNeedsReconciliation, readStateMigrationJournal(t, journalPath).Phase)
		})
	}
}

func TestStateMigration_RecoveryRejectsAliasedJournalPaths(t *testing.T) {
	root := coverageMigrationRoot(t)
	source := filepath.Join(root, "state.json")
	journalPath := filepath.Join(root, "migration.journal.json")
	original := []byte(`{"schema_version":1}`)
	desired := []byte(`{"schema_version":2}`)
	now := time.Date(2026, 8, 24, 16, 0, 0, 0, time.UTC)
	require.NoError(t, os.WriteFile(source, original, 0o600))

	tests := []struct {
		name   string
		mutate func(*StateMigrationJournal)
	}{
		{name: "backup does not use v1 suffix", mutate: func(journal *StateMigrationJournal) { journal.BackupPath = journal.SourcePath + ".backup" }},
		{name: "journal aliases source", mutate: func(journal *StateMigrationJournal) { journal.JournalPath = journal.SourcePath }},
		{name: "temporary aliases backup", mutate: func(journal *StateMigrationJournal) { journal.TempPath = journal.BackupPath }},
		{name: "temporary escapes source directory", mutate: func(journal *StateMigrationJournal) {
			journal.TempPath = filepath.Join(filepath.Dir(journal.SourcePath), "..", "outside")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			journal := coverageMigrationJournal(t, source, journalPath, filepath.Join(root, ".state.json.v2-temp"), "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhasePrepared, now)
			test.mutate(&journal)
			writeStateMigrationJournal(t, journalPath, journal)
			err := RecoverStateMigration(journalPath, now)
			require.ErrorIs(t, err, ErrStateMigrationInvalidJournal)
			assert.Equal(t, original, mustReadFile(t, source))
		})
	}
}

func TestStateMigration_MigrateRejectsNonRegularBackupArtifact(t *testing.T) {
	_, statePath, journalPath, manifest, publicKey, _, now, original := stateMigrationFixture(t)
	require.NoError(t, os.Mkdir(statePath+".v1", 0o700))
	err := MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-directory-backup", now)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a regular file")
	assert.Equal(t, original, mustReadFile(t, statePath))
}

func TestStateMigration_InputMatchingContractsAcceptOnlyExactArtifacts(t *testing.T) {
	root := coverageMigrationRoot(t)
	source := filepath.Join(root, "state.json")
	backup := source + ".v1"
	temp := filepath.Join(root, ".state.json.v2-temp")
	journalPath := filepath.Join(root, "migration.journal.json")
	original := []byte("original")
	desired := []byte("desired")
	now := time.Date(2026, 8, 24, 16, 30, 0, 0, time.UTC)
	journal := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhasePrepared, now)

	t.Run("committed inputs", func(t *testing.T) {
		require.NoError(t, os.WriteFile(source, desired, 0o600))
		require.NoError(t, os.WriteFile(backup, original, 0o600))
		require.NoError(t, os.WriteFile(temp, desired, 0o600))
		matched, err := migrationCommittedInputsMatch(&journal)
		require.NoError(t, err)
		assert.True(t, matched)
	})
	t.Run("recovery commit inputs", func(t *testing.T) {
		require.NoError(t, os.Remove(source))
		matched, err := migrationRecoveryCommitInputsMatch(&journal)
		require.NoError(t, err)
		assert.True(t, matched)
	})
	t.Run("rollback inputs", func(t *testing.T) {
		require.NoError(t, os.WriteFile(source, original, 0o600))
		require.NoError(t, os.Remove(backup))
		matched, err := migrationRollbackInputsMatch(&journal)
		require.NoError(t, err)
		assert.True(t, matched)
	})
	t.Run("committed state", func(t *testing.T) {
		require.NoError(t, os.WriteFile(source, desired, 0o600))
		require.NoError(t, os.WriteFile(backup, original, 0o600))
		require.NoError(t, os.Remove(temp))
		matched, err := migrationCommittedStateMatches(&journal)
		require.NoError(t, err)
		assert.True(t, matched)
		matched, err = committedMigrationMatchesJournal(&StateMigrationJournal{Phase: StateMigrationPhasePrepared})
		require.NoError(t, err)
		assert.False(t, matched)
	})
}

func TestStateMigration_RecoveryRejectsNonRegularInputArtifacts(t *testing.T) {
	now := time.Date(2026, 8, 24, 17, 0, 0, 0, time.UTC)
	original := []byte("original")
	desired := []byte("desired")
	tests := []struct {
		name  string
		which string
	}{
		{name: "source directory", which: "source"},
		{name: "backup directory", which: "backup"},
		{name: "temporary directory", which: "temp"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := coverageMigrationRoot(t)
			source := filepath.Join(root, "state.json")
			backup := source + ".v1"
			temp := filepath.Join(root, ".state.json.v2-temp")
			journalPath := filepath.Join(root, "migration.journal.json")
			require.NoError(t, os.WriteFile(source, original, 0o600))
			require.NoError(t, os.WriteFile(backup, original, 0o600))
			require.NoError(t, os.WriteFile(temp, desired, 0o600))
			switch test.which {
			case "source":
				require.NoError(t, os.Remove(source))
				require.NoError(t, os.Mkdir(source, 0o700))
			case "backup":
				require.NoError(t, os.Remove(backup))
				require.NoError(t, os.Mkdir(backup, 0o700))
			case "temp":
				require.NoError(t, os.Remove(temp))
				require.NoError(t, os.Mkdir(temp, 0o700))
			}
			journal := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhasePrepared, now)
			writeStateMigrationJournal(t, journalPath, journal)

			err := RecoverStateMigration(journalPath, now)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "original")
			assert.NotContains(t, err.Error(), "desired")
		})
	}
}

func TestStateMigration_RecoveryHooksAndJournalPersistenceFailuresAreFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 24, 17, 30, 0, 0, time.UTC)
	original := []byte("original")
	desired := []byte("desired")

	t.Run("recovery hook aborts before inspection", func(t *testing.T) {
		root := coverageMigrationRoot(t)
		source := filepath.Join(root, "state.json")
		backup := source + ".v1"
		temp := filepath.Join(root, ".state.json.v2-temp")
		journalPath := filepath.Join(root, "migration.journal.json")
		require.NoError(t, os.WriteFile(source, desired, 0o600))
		require.NoError(t, os.WriteFile(backup, original, 0o600))
		journal := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhasePrepared, now)
		writeStateMigrationJournal(t, journalPath, journal)
		originalHook := stateMigrationBeforeRecoveryCommit
		defer func() { stateMigrationBeforeRecoveryCommit = originalHook }()
		stateMigrationBeforeRecoveryCommit = func(*StateMigrationJournal) error {
			return errors.New("synthetic recovery hook failure")
		}

		err := RecoverStateMigration(journalPath, now)
		require.ErrorContains(t, err, "synthetic recovery hook failure")
		assert.Equal(t, StateMigrationPhasePrepared, readStateMigrationJournal(t, journalPath).Phase)
		assert.Equal(t, desired, mustReadFile(t, source))
	})

	t.Run("reconciliation journal persistence failure retains phase", func(t *testing.T) {
		root := coverageMigrationRoot(t)
		source := filepath.Join(root, "state.json")
		temp := filepath.Join(root, ".state.json.v2-temp")
		targetDirectory := filepath.Join(root, "journal-directory")
		require.NoError(t, os.Mkdir(targetDirectory, 0o700))
		journal := coverageMigrationJournal(t, source, targetDirectory, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhasePrepared, now)

		err := markMigrationNeedsReconciliation(&journal, now)
		require.ErrorContains(t, err, "commit journal")
		assert.Equal(t, StateMigrationPhaseNeedsReconciliation, journal.Phase)
	})

	t.Run("commit journal persistence failure leaves metadata uncommitted", func(t *testing.T) {
		root := coverageMigrationRoot(t)
		source := filepath.Join(root, "state.json")
		temp := filepath.Join(root, ".state.json.v2-temp")
		targetDirectory := filepath.Join(root, "journal-directory")
		require.NoError(t, os.Mkdir(targetDirectory, 0o700))
		journal := coverageMigrationJournal(t, source, targetDirectory, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhaseCommitted, now)

		err := persistMigrationJournal(&journal)
		require.ErrorContains(t, err, "commit journal")
	})
}

func TestStateMigration_PersistAndLoadJournalErrorBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 24, 18, 0, 0, 0, time.UTC)
	root := coverageMigrationRoot(t)
	source := filepath.Join(root, "state.json")
	temp := filepath.Join(root, ".state.json.v2-temp")
	journalPath := filepath.Join(root, "migration.journal.json")
	original := []byte("original")
	desired := []byte("desired")
	valid := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhasePrepared, now)

	require.ErrorIs(t, validateMigrationJournal(nil, ""), ErrStateMigrationInvalidJournal)
	invalid := valid
	invalid.Version++
	require.ErrorIs(t, persistMigrationJournal(&invalid), ErrStateMigrationInvalidJournal)

	missingParent := valid
	missingParent.JournalPath = filepath.Join(root, "missing", "journal.json")
	missingParent.SourcePath = filepath.Join(root, "missing", "state.json")
	missingParent.BackupPath = missingParent.SourcePath + ".v1"
	missingParent.TempPath = filepath.Join(root, "missing", ".state.json.v2-temp")
	require.ErrorContains(t, persistMigrationJournal(&missingParent), "create journal temporary file")

	targetDirectory := filepath.Join(root, "journal-directory")
	require.NoError(t, os.Mkdir(targetDirectory, 0o700))
	directoryJournal := valid
	directoryJournal.JournalPath = targetDirectory
	require.ErrorContains(t, persistMigrationJournal(&directoryJournal), "commit journal")

	if _, err := loadMigrationJournalIfPresent(filepath.Join(root, "absent.json")); err != nil {
		t.Fatalf("missing journal should be treated as absent: %v", err)
	}
	loaded, err := loadMigrationJournalIfPresent(filepath.Join(root, "absent.json"))
	require.NoError(t, err)
	assert.Nil(t, loaded)
	_, err = loadMigrationJournal(filepath.Join(root, "absent.json"))
	require.ErrorContains(t, err, "read journal")
}

func TestStateMigration_JournalValidationRejectsEveryMutableInvariant(t *testing.T) {
	now := time.Date(2026, 8, 24, 18, 30, 0, 0, time.UTC)
	root := coverageMigrationRoot(t)
	source := filepath.Join(root, "state.json")
	journalPath := filepath.Join(root, "migration.journal.json")
	temp := filepath.Join(root, ".state.json.v2-temp")
	base := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), []byte("original"), []byte("desired"), StateMigrationPhasePrepared, now)
	tests := []struct {
		name   string
		mutate func(*StateMigrationJournal)
	}{
		{name: "empty operation id", mutate: func(journal *StateMigrationJournal) { journal.OperationID = "" }},
		{name: "invalid manifest digest", mutate: func(journal *StateMigrationJournal) { journal.ManifestDigest = "bad" }},
		{name: "invalid source hash", mutate: func(journal *StateMigrationJournal) { journal.SourceHash = "bad" }},
		{name: "invalid desired hash", mutate: func(journal *StateMigrationJournal) { journal.DesiredHash = "bad" }},
		{name: "negative source size", mutate: func(journal *StateMigrationJournal) { journal.SourceSize = -1 }},
		{name: "negative desired size", mutate: func(journal *StateMigrationJournal) { journal.DesiredSize = -1 }},
		{name: "zero created time", mutate: func(journal *StateMigrationJournal) { journal.CreatedAt = time.Time{} }},
		{name: "zero updated time", mutate: func(journal *StateMigrationJournal) { journal.UpdatedAt = time.Time{} }},
		{name: "invalid phase", mutate: func(journal *StateMigrationJournal) { journal.Phase = StateMigrationPhase("invalid") }},
		{name: "wrong backup path", mutate: func(journal *StateMigrationJournal) { journal.BackupPath = journal.SourcePath + ".backup" }},
		{name: "expected path mismatch", mutate: func(journal *StateMigrationJournal) { journal.JournalPath = filepath.Join(root, "other.json") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			journal := base
			test.mutate(&journal)
			require.ErrorIs(t, validateMigrationJournal(&journal, journalPath), ErrStateMigrationInvalidJournal)
		})
	}
}

func TestStateMigration_StatePathOutsideManifestFileSetFailsClosed(t *testing.T) {
	root, _, _, manifest, _, _, _, original := stateMigrationFixture(t)
	otherPath := filepath.Join(root, "not-a-manifest-file")
	require.NoError(t, os.WriteFile(otherPath, []byte("outside"), 0o600))

	_, err := stateManifestRowForPath(manifest, otherPath)
	require.ErrorContains(t, err, "source file is not in manifest")
	assert.Equal(t, original, mustReadFile(t, filepath.Join(root, "state.json")))
}

func TestStateMigration_FileTransitionHelpersFailClosed(t *testing.T) {
	root := coverageMigrationRoot(t)
	source := filepath.Join(root, "state.json")
	backup := source + ".v1"
	temp := filepath.Join(root, ".state.json.v2-temp")
	journalPath := filepath.Join(root, "migration.journal.json")
	original := []byte("original")
	desired := []byte("desired")
	now := time.Date(2026, 8, 24, 19, 0, 0, 0, time.UTC)
	journal := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhasePrepared, now)

	t.Run("inspect missing file is absent", func(t *testing.T) {
		info, err := inspectMigrationFile(filepath.Join(root, "missing"))
		require.NoError(t, err)
		assert.False(t, info.exists)
	})
	t.Run("remove exact file rejects changed content", func(t *testing.T) {
		require.NoError(t, os.WriteFile(temp, desired, 0o600))
		err := removeMigrationFileIfExact(temp, stateMigrationHash(original), int64(len(original)))
		require.ErrorContains(t, err, "changed during recovery")
		assert.Equal(t, desired, mustReadFile(t, temp))
		require.NoError(t, os.Remove(temp))
	})
	t.Run("link rejects missing source and occupied destination", func(t *testing.T) {
		err := linkMigrationExclusively(filepath.Join(root, "missing"), filepath.Join(root, "destination"))
		require.Error(t, err)
		require.NoError(t, os.WriteFile(source, original, 0o600))
		require.NoError(t, os.WriteFile(backup, []byte("occupied"), 0o600))
		err = linkMigrationExclusively(source, backup)
		require.Error(t, err)
		require.NoError(t, os.Remove(backup))
	})
	t.Run("commit temp links then removes temp", func(t *testing.T) {
		require.NoError(t, os.Remove(source))
		require.NoError(t, os.WriteFile(temp, desired, 0o600))
		require.NoError(t, commitMigrationTempExclusively(temp, source))
		assert.Equal(t, desired, mustReadFile(t, source))
		assert.NoFileExists(t, temp)
		require.NoError(t, os.Remove(source))
	})
	t.Run("secure missing file reports failure", func(t *testing.T) {
		require.ErrorContains(t, secureMigrationFile(filepath.Join(root, "missing")), "secure recovery file")
	})
	t.Run("preservation rejects changed source and existing backup", func(t *testing.T) {
		require.NoError(t, os.WriteFile(source, []byte("changed"), 0o600))
		err := preserveMigrationSourceExclusively(&journal)
		require.ErrorContains(t, err, "changed before preservation")
		require.NoError(t, os.Remove(source))
		require.NoError(t, os.WriteFile(source, original, 0o600))
		require.NoError(t, os.WriteFile(backup, original, 0o600))
		err = preserveMigrationSourceExclusively(&journal)
		require.ErrorContains(t, err, "backup already exists")
		require.NoError(t, os.Remove(backup))
	})
	t.Run("preservation hook aborts after exclusive link", func(t *testing.T) {
		require.NoError(t, os.WriteFile(source, original, 0o600))
		originalHook := stateMigrationBeforeSourceBackupRemove
		defer func() { stateMigrationBeforeSourceBackupRemove = originalHook }()
		stateMigrationBeforeSourceBackupRemove = func(*StateMigrationJournal) error {
			return errors.New("synthetic preservation hook failure")
		}
		err := preserveMigrationSourceExclusively(&journal)
		require.ErrorContains(t, err, "synthetic preservation hook failure")
		assert.Equal(t, original, mustReadFile(t, source))
		assert.Equal(t, original, mustReadFile(t, backup))
		require.NoError(t, os.Remove(source))
		require.NoError(t, os.Remove(backup))
	})
	t.Run("backup validation rejects changed source", func(t *testing.T) {
		require.NoError(t, os.WriteFile(source, original, 0o600))
		err := validateMigrationBackupAfterRename(&journal)
		require.ErrorContains(t, err, "source or backup changed")
		require.NoError(t, os.Remove(source))
	})
	t.Run("restore rejects appeared source and bad backup", func(t *testing.T) {
		require.NoError(t, os.WriteFile(source, original, 0o600))
		require.NoError(t, os.WriteFile(backup, original, 0o600))
		err := restoreMigrationSourceFromBackup(&journal)
		require.ErrorContains(t, err, "source appeared during recovery")
		require.NoError(t, os.Remove(source))
		require.NoError(t, os.WriteFile(backup, []byte("bad-backup"), 0o600))
		err = restoreMigrationSourceFromBackup(&journal)
		require.ErrorContains(t, err, "hash or size mismatch")
	})
}

func TestStateMigration_MigrateDecodesManifestMatchedInvalidV1Objects(t *testing.T) {
	now := time.Date(2026, 8, 24, 19, 30, 0, 0, time.UTC)
	tests := []struct {
		name string
		body []byte
	}{
		{name: "array", body: []byte(`[]`)},
		{name: "schema v2", body: []byte(`{"schema_version":2}`)},
		{name: "schema malformed", body: []byte(`{"schema_version":"one"}`)},
		{name: "trailing data", body: []byte(`{"schema_version":1} trailing`)},
		{name: "null object", body: []byte(`null`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, statePath, journalPath, _, publicKey, privateKey, _, _ := stateMigrationFixture(t)
			require.NoError(t, os.WriteFile(statePath, test.body, 0o600))
			manifest, err := BuildStateManifest(root, "operator", "hub", "nonce-invalid-v1", now.Add(time.Minute), privateKey, now)
			require.NoError(t, err)

			err = MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-invalid-v1", now)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "sensitive")
			assert.NoFileExists(t, statePath+".v1")
			assert.NoFileExists(t, journalPath)
		})
	}
}

func TestStateMigration_MigrateJournalPersistenceFailuresRetainRecoveryArtifacts(t *testing.T) {
	t.Run("prepared journal persistence fails before mutation", func(t *testing.T) {
		_, statePath, journalPath, manifest, publicKey, _, now, original := stateMigrationFixture(t)
		originalPersist := stateMigrationPersistJournal
		defer func() { stateMigrationPersistJournal = originalPersist }()
		stateMigrationPersistJournal = func(*StateMigrationJournal) error {
			return errors.New("synthetic prepared journal failure")
		}

		err := MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-prepared-persist-failure", now)
		require.ErrorContains(t, err, "synthetic prepared journal failure")
		assert.Equal(t, original, mustReadFile(t, statePath))
		assert.NoFileExists(t, statePath+".v1")
		assert.Empty(t, migrationTempFiles(t, filepath.Dir(statePath)))
	})

	t.Run("committed journal persistence fails after files commit", func(t *testing.T) {
		_, statePath, journalPath, manifest, publicKey, _, now, original := stateMigrationFixture(t)
		originalPersist := stateMigrationPersistJournal
		defer func() { stateMigrationPersistJournal = originalPersist }()
		var calls int
		stateMigrationPersistJournal = func(journal *StateMigrationJournal) error {
			calls++
			if calls == 3 {
				return errors.New("synthetic committed journal failure")
			}
			return persistMigrationJournal(journal)
		}

		err := MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-committed-persist-failure", now)
		require.ErrorContains(t, err, "synthetic committed journal failure")
		assert.Equal(t, stateMigrationV2Bytes(t, original, stateMigrationManifestDigest(t, manifest)), mustReadFile(t, statePath))
		assert.Equal(t, original, mustReadFile(t, statePath+".v1"))
		assert.Equal(t, StateMigrationPhaseBackupRenamed, readStateMigrationJournal(t, journalPath).Phase)
	})
}

func TestStateMigration_ValidationHelperContracts(t *testing.T) {
	t.Run("operation identifiers fail closed", func(t *testing.T) {
		tests := []string{"", ".", "..", " leading", "trailing ", "bad/id", "bad id", strings.Repeat("x", 129)}
		for _, value := range tests {
			require.Error(t, validateStateMigrationOperationID(value), value)
		}
		require.NoError(t, validateStateMigrationOperationID("op-coverage_1.2"))
	})

	t.Run("paths require absolute clean names", func(t *testing.T) {
		traversal := filepath.Join(coverageMigrationRoot(t), "child") + string(filepath.Separator) + ".." + string(filepath.Separator) + "outside"
		tests := []string{"", "relative/path", traversal, filepath.Join(coverageMigrationRoot(t), "nul\x00path")}
		for _, value := range tests {
			require.Error(t, validateMigrationPath(value), value)
		}
		clean := filepath.Join(coverageMigrationRoot(t), "state.json")
		require.NoError(t, validateMigrationPath(clean))
	})

	t.Run("migration path relationships are exclusive", func(t *testing.T) {
		root := coverageMigrationRoot(t)
		source := filepath.Join(root, "state.json")
		backup := source + ".v1"
		temp := filepath.Join(root, ".state.json.v2-temp")
		journal := filepath.Join(root, "migration.journal.json")
		tests := []struct {
			name   string
			mutate func(*string, *string, *string, *string)
		}{
			{name: "wrong backup suffix", mutate: func(_, backup, _, _ *string) { *backup = filepath.Join(root, "backup") }},
			{name: "temporary escapes source directory", mutate: func(_, _, temp, _ *string) { *temp = filepath.Join(root, "other", "temp") }},
			{name: "temporary aliases source", mutate: func(source, _, temp, _ *string) { *temp = *source }},
			{name: "temporary aliases backup", mutate: func(_, backup, temp, _ *string) { *temp = *backup }},
			{name: "journal aliases source", mutate: func(source, _, _, journal *string) { *journal = *source }},
			{name: "journal aliases backup", mutate: func(_, backup, _, journal *string) { *journal = *backup }},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				currentSource, currentBackup, currentTemp, currentJournal := source, backup, temp, journal
				test.mutate(&currentSource, &currentBackup, &currentTemp, &currentJournal)
				require.Error(t, validateMigrationPaths(currentSource, currentBackup, currentTemp, currentJournal))
			})
		}
		require.NoError(t, validateMigrationPaths(source, backup, temp, journal))
	})

	t.Run("manifest rows reject escapes and return exact rows", func(t *testing.T) {
		root, statePath, _, manifest, _, _, _, _ := stateMigrationFixture(t)
		row, err := stateManifestRowForPath(manifest, statePath)
		require.NoError(t, err)
		assert.Equal(t, "state.json", row.Path)
		require.Error(t, func() error {
			_, err := stateManifestRowForPath(manifest, statePath+string(filepath.Separator)+".")
			return err
		}())
		require.Error(t, func() error {
			_, err := stateManifestRowForPath(manifest, filepath.Join(root, "..", "outside"))
			return err
		}())
		require.Error(t, func() error {
			_, err := stateManifestRowForPath(manifest, filepath.Join(root, "not-listed"))
			return err
		}())
	})

	t.Run("v1 decoder enforces one object and schema", func(t *testing.T) {
		tests := [][]byte{
			[]byte(`[`),
			[]byte(`[]`),
			[]byte(`null`),
			[]byte(`{"schema_version":2}`),
			[]byte(`{"schema_version":"one"}`),
			[]byte(`{"schema_version":1} trailing`),
		}
		for _, body := range tests {
			_, err := decodeV1StateObject(body)
			require.Error(t, err)
		}
		object, err := decodeV1StateObject([]byte(`{"schema_version":1,"key":"value"}`))
		require.NoError(t, err)
		assert.Contains(t, object, "key")
	})

	t.Run("hash and digest syntax is strict", func(t *testing.T) {
		validHash := strings.Repeat("a", 64)
		require.True(t, validStateMigrationHash(validHash))
		require.False(t, validStateMigrationHash(strings.Repeat("A", 64)))
		require.False(t, validStateMigrationHash(strings.Repeat("a", 63)))
		require.False(t, validStateMigrationHash(strings.Repeat("g", 64)))
		require.True(t, validStateMigrationDigest("sha256:"+validHash))
		require.False(t, validStateMigrationDigest(validHash))
		require.False(t, validStateMigrationDigest("sha256:"+strings.Repeat("A", 64)))
	})
}

func TestStateMigration_FileInspectionAndMatchingContracts(t *testing.T) {
	root := coverageMigrationRoot(t)
	source := filepath.Join(root, "state.json")
	backup := source + ".v1"
	temp := filepath.Join(root, ".state.json.v2-temp")
	journalPath := filepath.Join(root, "migration.journal.json")
	original := []byte("original")
	desired := []byte("desired")
	now := time.Date(2026, 8, 24, 20, 0, 0, 0, time.UTC)
	journal := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhaseCommitted, now)

	require.NoError(t, os.WriteFile(source, desired, 0o600))
	require.NoError(t, os.WriteFile(backup, original, 0o600))
	require.NoError(t, os.WriteFile(temp, desired, 0o600))

	t.Run("path exists distinguishes missing regular and directory", func(t *testing.T) {
		exists, err := migrationPathExists(source)
		require.NoError(t, err)
		assert.True(t, exists)
		exists, err = migrationPathExists(filepath.Join(root, "missing"))
		require.NoError(t, err)
		assert.False(t, exists)
		directory := filepath.Join(root, "directory")
		require.NoError(t, os.Mkdir(directory, 0o700))
		_, err = migrationPathExists(directory)
		require.ErrorContains(t, err, "not a regular file")
	})
	t.Run("regular reader returns bytes and rejects nonregular paths", func(t *testing.T) {
		read, err := readRegularMigrationFile(source)
		require.NoError(t, err)
		assert.Equal(t, desired, read)
		_, err = readRegularMigrationFile(filepath.Join(root, "missing"))
		require.Error(t, err)
		directory := filepath.Join(root, "read-directory")
		require.NoError(t, os.Mkdir(directory, 0o700))
		_, err = readRegularMigrationFile(directory)
		require.ErrorContains(t, err, "not a regular file")
	})
	t.Run("inspect and matches bind both hash and size", func(t *testing.T) {
		info, err := inspectMigrationFile(source)
		require.NoError(t, err)
		assert.True(t, info.matches(stateMigrationHash(desired), int64(len(desired))))
		assert.False(t, info.matches(stateMigrationHash(original), int64(len(original))))
		missing, err := inspectMigrationFile(filepath.Join(root, "missing-inspection"))
		require.NoError(t, err)
		assert.False(t, missing.exists)
		directory := filepath.Join(root, "inspect-directory")
		require.NoError(t, os.Mkdir(directory, 0o700))
		_, err = inspectMigrationFile(directory)
		require.ErrorContains(t, err, "not a regular file")
	})
	t.Run("committed file validation rejects each artifact mismatch", func(t *testing.T) {
		require.NoError(t, os.Remove(temp))
		require.NoError(t, validateCommittedMigrationFiles(&journal))
		require.NoError(t, os.WriteFile(source, original, 0o600))
		require.ErrorContains(t, validateCommittedMigrationFiles(&journal), "committed source changed")
		require.NoError(t, os.WriteFile(source, desired, 0o600))
		require.NoError(t, os.WriteFile(backup, []byte("bad-backup"), 0o600))
		require.ErrorContains(t, validateCommittedMigrationFiles(&journal), "preserved v1 changed")
		require.NoError(t, os.WriteFile(backup, original, 0o600))
		require.NoError(t, os.WriteFile(temp, desired, 0o600))
		require.ErrorContains(t, validateCommittedMigrationFiles(&journal), "temporary file remains")
		require.NoError(t, os.Remove(temp))
	})
	t.Run("input matching returns false for changed files", func(t *testing.T) {
		require.NoError(t, os.WriteFile(source, []byte("wrong-source"), 0o600))
		matched, err := migrationCommittedInputsMatch(&journal)
		require.NoError(t, err)
		assert.False(t, matched)
		require.NoError(t, os.WriteFile(source, desired, 0o600))
		require.NoError(t, os.Remove(backup))
		matched, err = migrationCommittedInputsMatch(&journal)
		require.NoError(t, err)
		assert.False(t, matched)
		require.NoError(t, os.WriteFile(backup, original, 0o600))
		require.NoError(t, os.Remove(source))
		matched, err = migrationRecoveryCommitInputsMatch(&journal)
		require.NoError(t, err)
		assert.False(t, matched)
		require.NoError(t, os.WriteFile(source, original, 0o600))
		matched, err = migrationRollbackInputsMatch(&journal)
		require.NoError(t, err)
		assert.False(t, matched)
	})
	t.Run("committed migration identity checks metadata and files", func(t *testing.T) {
		require.NoError(t, os.WriteFile(source, desired, 0o600))
		require.NoError(t, os.WriteFile(backup, original, 0o600))
		journal.Phase = StateMigrationPhaseCommitted
		matched, err := committedMigrationMatchesJournal(&journal)
		require.NoError(t, err)
		assert.True(t, matched)
		matched, err = committedMigrationMatchesJournal(&StateMigrationJournal{Phase: StateMigrationPhasePrepared})
		require.NoError(t, err)
		assert.False(t, matched)

		matched, err = committedMigrationMatches(filepath.Join(root, "missing-journal"), source, journal.OperationID, journal.ManifestDigest)
		require.NoError(t, err)
		assert.False(t, matched)
		journalPath = filepath.Join(root, "identity.journal.json")
		journal.JournalPath = journalPath
		writeStateMigrationJournal(t, journalPath, journal)
		matched, err = committedMigrationMatches(journalPath, source, "other-operation", journal.ManifestDigest)
		require.NoError(t, err)
		assert.False(t, matched)
	})
}

func TestStateMigration_MigrateAcceptsLegacyObjectWithoutSchemaField(t *testing.T) {
	root, statePath, journalPath, _, publicKey, privateKey, now, original := stateMigrationFixture(t)
	legacy := []byte(`{"target":"synthetic","metadata":"legacy-no-schema"}`)
	require.NoError(t, os.WriteFile(statePath, legacy, 0o600))
	manifest, err := BuildStateManifest(root, "operator", "hub", "nonce-no-schema", now.Add(time.Minute), privateKey, now)
	require.NoError(t, err)

	require.NoError(t, MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-no-schema", now))
	assert.Contains(t, string(mustReadFile(t, statePath)), `"schema_version":2`)
	assert.Equal(t, legacy, mustReadFile(t, statePath+".v1"))
	assert.NotContains(t, string(mustReadFile(t, journalPath)), "legacy-no-schema")
	assert.NotEqual(t, original, mustReadFile(t, statePath))
}

func TestStateMigration_MigrateManifestScopeFailuresNeverMutate(t *testing.T) {
	_, statePath, journalPath, manifest, publicKey, _, now, original := stateMigrationFixture(t)
	tests := []struct {
		name string
		role string
		aud  string
		key  []byte
		when time.Time
	}{
		{name: "wrong role", role: "other-role", aud: "hub", key: publicKey, when: now},
		{name: "wrong audience", role: "operator", aud: "other-audience", key: publicKey, when: now},
		{name: "invalid verifier key", role: "operator", aud: "hub", key: []byte("short"), when: now},
		{name: "expired manifest", role: "operator", aud: "hub", key: publicKey, when: now.Add(10 * time.Minute)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := MigrateStateFileV1ToV2(statePath, journalPath, manifest, test.key, test.role, test.aud, "op-scope-failure", test.when)
			require.Error(t, err)
			assert.Equal(t, original, mustReadFile(t, statePath))
			assert.NoFileExists(t, statePath+".v1")
			assert.NoFileExists(t, journalPath)
			assert.Empty(t, migrationTempFiles(t, filepath.Dir(statePath)))
		})
	}
}

func TestStateMigration_CommitAndAncestorHelpersRejectInvalidJournalState(t *testing.T) {
	root := coverageMigrationRoot(t)
	source := filepath.Join(root, "state.json")
	backup := source + ".v1"
	temp := filepath.Join(root, ".state.json.v2-temp")
	journalPath := filepath.Join(root, "migration.journal.json")
	now := time.Date(2026, 8, 24, 21, 0, 0, 0, time.UTC)
	journal := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), []byte("original"), []byte("desired"), StateMigrationPhaseCommitted, now)

	require.ErrorIs(t, validateCommittedMigrationFiles(nil), ErrStateMigrationInvalidJournal)
	require.Error(t, validateMigrationMutationAncestors(filepath.Join(root, "missing", "state.json")))
	require.Error(t, validateMigrationRequestPaths("relative-state", journalPath))
	require.Error(t, validateMigrationRequestPaths(source, "relative-journal"))

	invalid := journal
	invalid.SourcePath = filepath.Join(root, "missing", "state.json")
	require.Error(t, func() error {
		_, err := migrationCommittedInputsMatch(&invalid)
		return err
	}())
	require.Error(t, func() error {
		_, err := migrationRecoveryCommitInputsMatch(&invalid)
		return err
	}())
	require.Error(t, func() error {
		_, err := migrationRollbackInputsMatch(&invalid)
		return err
	}())
	require.Error(t, func() error {
		_, err := migrationCommittedStateMatches(&invalid)
		return err
	}())

	require.NoError(t, os.WriteFile(source, []byte("desired"), 0o600))
	require.NoError(t, os.WriteFile(backup, []byte("original"), 0o600))
	writeStateMigrationJournal(t, journalPath, journal)
	for _, mutate := range []func(*StateMigrationJournal){
		func(value *StateMigrationJournal) { value.OperationID = "other" },
		func(value *StateMigrationJournal) { value.ManifestDigest = "sha256:" + strings.Repeat("b", 64) },
		func(value *StateMigrationJournal) {
			value.SourcePath = filepath.Join(root, "other-state.json")
			value.BackupPath = value.SourcePath + ".v1"
			value.TempPath = filepath.Join(root, ".other-state.json.v2-temp")
		},
		func(value *StateMigrationJournal) { value.Phase = StateMigrationPhasePrepared },
	} {
		stored := journal
		mutate(&stored)
		writeStateMigrationJournal(t, journalPath, stored)
		matched, err := committedMigrationMatches(journalPath, source, journal.OperationID, journal.ManifestDigest)

		require.NoError(t, err)
		assert.False(t, matched)
	}
}

func TestStateMigration_JournalAndRestoreRoundTrips(t *testing.T) {
	now := time.Date(2026, 8, 24, 21, 30, 0, 0, time.UTC)
	original := []byte("original")
	desired := []byte("desired")

	t.Run("persist and load a value-free journal", func(t *testing.T) {
		root := coverageMigrationRoot(t)
		source := filepath.Join(root, "state.json")
		journalPath := filepath.Join(root, "migration.journal.json")
		temp := filepath.Join(root, ".state.json.v2-temp")
		journal := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhasePrepared, now)
		require.NoError(t, persistMigrationJournal(&journal))
		loaded, err := loadMigrationJournal(journalPath)
		require.NoError(t, err)
		assert.Equal(t, journal, *loaded)
		data := mustReadFile(t, journalPath)
		assert.NotContains(t, string(data), `"`+string(original)+`"`)
		assert.NotContains(t, string(data), `"`+string(desired)+`"`)
	})

	t.Run("mark reconciliation persists terminal phase", func(t *testing.T) {
		root := coverageMigrationRoot(t)
		source := filepath.Join(root, "state.json")
		journalPath := filepath.Join(root, "migration.journal.json")
		temp := filepath.Join(root, ".state.json.v2-temp")
		journal := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhasePrepared, now)
		require.ErrorIs(t, markMigrationNeedsReconciliation(&journal, now.Add(time.Minute)), ErrStateMigrationNeedsReconciliation)
		require.ErrorIs(t, RecoverStateMigration(journalPath, now.Add(2*time.Minute)), ErrStateMigrationNeedsReconciliation)
		assert.Equal(t, StateMigrationPhaseNeedsReconciliation, readStateMigrationJournal(t, journalPath).Phase)
	})

	t.Run("backup validation accepts exact preserved source", func(t *testing.T) {
		root := coverageMigrationRoot(t)
		source := filepath.Join(root, "state.json")
		backup := source + ".v1"
		journalPath := filepath.Join(root, "migration.journal.json")
		temp := filepath.Join(root, ".state.json.v2-temp")
		journal := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhaseBackupRenamed, now)
		require.NoError(t, os.WriteFile(backup, original, 0o600))
		require.NoError(t, validateMigrationBackupAfterRename(&journal))
	})

	t.Run("preserve and restore source use exact bytes", func(t *testing.T) {
		root := coverageMigrationRoot(t)
		source := filepath.Join(root, "state.json")
		backup := source + ".v1"
		journalPath := filepath.Join(root, "migration.journal.json")
		temp := filepath.Join(root, ".state.json.v2-temp")
		journal := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhasePrepared, now)
		require.NoError(t, os.WriteFile(source, original, 0o600))
		require.NoError(t, preserveMigrationSourceExclusively(&journal))
		assert.NoFileExists(t, source)
		assert.Equal(t, original, mustReadFile(t, backup))
		require.NoError(t, restoreMigrationSourceFromBackup(&journal))
		assert.Equal(t, original, mustReadFile(t, source))
		assert.Equal(t, original, mustReadFile(t, backup))
	})
}

func TestStateMigration_RecoveryCompletesPreparedAndBackupRenamedTransitions(t *testing.T) {
	now := time.Date(2026, 8, 24, 22, 0, 0, 0, time.UTC)
	original := []byte("original")
	desired := []byte("desired")

	t.Run("prepared rollback removes only exact temporary state", func(t *testing.T) {
		root := coverageMigrationRoot(t)
		source := filepath.Join(root, "state.json")
		journalPath := filepath.Join(root, "migration.journal.json")
		temp := filepath.Join(root, ".state.json.v2-temp")
		require.NoError(t, os.WriteFile(source, original, 0o600))
		require.NoError(t, os.WriteFile(temp, desired, 0o600))
		journal := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhasePrepared, now)
		writeStateMigrationJournal(t, journalPath, journal)

		require.ErrorIs(t, RecoverStateMigration(journalPath, now.Add(time.Minute)), ErrStateMigrationNeedsReconciliation)
		assert.Equal(t, original, mustReadFile(t, source))
		assert.NoFileExists(t, temp)
		assert.Equal(t, StateMigrationPhaseNeedsReconciliation, readStateMigrationJournal(t, journalPath).Phase)
	})

	t.Run("prepared recovery restores the preserved source", func(t *testing.T) {
		root := coverageMigrationRoot(t)
		source := filepath.Join(root, "state.json")
		journalPath := filepath.Join(root, "migration.journal.json")
		backup := source + ".v1"
		temp := filepath.Join(root, ".state.json.v2-temp")
		require.NoError(t, os.WriteFile(backup, original, 0o600))
		require.NoError(t, os.WriteFile(temp, desired, 0o600))
		journal := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhasePrepared, now)
		writeStateMigrationJournal(t, journalPath, journal)

		require.ErrorIs(t, RecoverStateMigration(journalPath, now.Add(time.Minute)), ErrStateMigrationNeedsReconciliation)
		assert.Equal(t, original, mustReadFile(t, source))
		assert.Equal(t, original, mustReadFile(t, backup))
		assert.NoFileExists(t, temp)
		assert.Equal(t, StateMigrationPhaseNeedsReconciliation, readStateMigrationJournal(t, journalPath).Phase)
	})

	t.Run("backup-renamed recovery commits the prepared v2 state", func(t *testing.T) {
		root := coverageMigrationRoot(t)
		source := filepath.Join(root, "state.json")
		journalPath := filepath.Join(root, "migration.journal.json")
		backup := source + ".v1"
		temp := filepath.Join(root, ".state.json.v2-temp")
		require.NoError(t, os.WriteFile(backup, original, 0o600))
		require.NoError(t, os.WriteFile(temp, desired, 0o600))
		journal := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhaseBackupRenamed, now)
		writeStateMigrationJournal(t, journalPath, journal)

		require.NoError(t, RecoverStateMigration(journalPath, now.Add(time.Minute)))
		assert.Equal(t, desired, mustReadFile(t, source))
		assert.Equal(t, original, mustReadFile(t, backup))
		assert.NoFileExists(t, temp)
		assert.Equal(t, StateMigrationPhaseCommitted, readStateMigrationJournal(t, journalPath).Phase)
	})
}

func TestStateMigration_RecoveryBackupRenamedAlreadyCommittedWithoutTemp(t *testing.T) {
	now := time.Date(2026, 8, 24, 22, 15, 0, 0, time.UTC)
	root := coverageMigrationRoot(t)
	source := filepath.Join(root, "state.json")
	backup := source + ".v1"
	journalPath := filepath.Join(root, "migration.journal.json")
	temp := filepath.Join(root, ".state.json.v2-temp")
	original := []byte("original")
	desired := []byte("desired")
	require.NoError(t, os.WriteFile(source, desired, 0o600))
	require.NoError(t, os.WriteFile(backup, original, 0o600))
	journal := coverageMigrationJournal(t, source, journalPath, temp, "sha256:"+strings.Repeat("a", 64), original, desired, StateMigrationPhaseBackupRenamed, now)
	writeStateMigrationJournal(t, journalPath, journal)

	require.NoError(t, RecoverStateMigration(journalPath, now.Add(time.Minute)))
	assert.Equal(t, StateMigrationPhaseCommitted, readStateMigrationJournal(t, journalPath).Phase)
	assert.Equal(t, desired, mustReadFile(t, source))
	assert.Equal(t, original, mustReadFile(t, backup))
	assert.NoFileExists(t, temp)
}

func TestStateMigration_MigrateCommittedJournalIsIdempotentAfterManifestReadback(t *testing.T) {
	root, statePath, journalPath, manifest, publicKey, _, now, original := stateMigrationFixture(t)
	manifestDigest := stateMigrationManifestDigest(t, manifest)
	desired := stateMigrationV2Bytes(t, original, manifestDigest)
	require.NoError(t, os.WriteFile(statePath, desired, 0o600))
	require.NoError(t, os.WriteFile(statePath+".v1", original, 0o600))
	journal := coverageMigrationJournal(t, statePath, journalPath, filepath.Join(root, ".state.json.v2-temp"), manifestDigest, original, desired, StateMigrationPhaseCommitted, now)
	writeStateMigrationJournal(t, journalPath, journal)

	require.NoError(t, MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", journal.OperationID, now))
	assert.Equal(t, desired, mustReadFile(t, statePath))
	assert.Equal(t, original, mustReadFile(t, statePath+".v1"))
}
