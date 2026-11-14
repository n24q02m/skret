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

var (
	coverageHelperOriginal = []byte(`{"schema_version":1,"value":"v1"}`)
	coverageHelperDesired  = []byte(`{"schema_version":2,"value":"v2"}`)
)

// coverageHelperJournal returns a journal whose artifacts live in a fresh
// root; nothing is written to disk.
func coverageHelperJournal(t *testing.T, phase StateMigrationPhase) (*StateMigrationJournal, string) {
	t.Helper()
	root := coverageMigrationRoot(t)
	source := filepath.Join(root, "state.json")
	journalDir := coverageMigrationRoot(t)
	journal := coverageMigrationJournal(t, source, filepath.Join(journalDir, "migration.journal.json"), filepath.Join(root, ".state.json.v2-temp"), "sha256:"+stateMigrationHash([]byte("manifest")), coverageHelperOriginal, coverageHelperDesired, phase, time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC))
	return &journal, root
}

// coverageMissingDirJournal points every artifact into a directory that does
// not exist so ancestor validation fails.
func coverageMissingDirJournal(t *testing.T, phase StateMigrationPhase) *StateMigrationJournal {
	t.Helper()
	journal, root := coverageHelperJournal(t, phase)
	missing := filepath.Join(root, "missing")
	journal.SourcePath = filepath.Join(missing, "state.json")
	journal.BackupPath = journal.SourcePath + ".v1"
	journal.TempPath = filepath.Join(missing, ".state.json.v2-temp")
	return journal
}

func TestStateMigrationHelpers_PathValidationRejectsRelativeInputs(t *testing.T) {
	root := coverageMigrationRoot(t)
	source := filepath.Join(root, "state.json")
	journal := filepath.Join(root, "journal.json")

	err := validateMigrationPaths("state.json", "state.json.v1", "", journal)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid path")

	err = validateMigrationPaths(source, source+".v1", ".state.json.v2-temp", journal)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid path")

	_, err = stateManifestRowForPath(&StateManifest{SourceRoot: filepath.Join(root, "missing-root")}, source)
	require.Error(t, err)
}

func TestStateMigrationHelpers_ReadAndInspectErrors(t *testing.T) {
	root := coverageMigrationRoot(t)
	lstatErr := faultLstatErrorPath(t, coverageMigrationRoot(t))

	_, err := migrationPathExists(lstatErr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inspect path")

	_, err = loadMigrationJournalIfPresent(lstatErr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inspect journal")

	_, err = inspectMigrationFile(lstatErr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inspect file")

	unreadable := filepath.Join(root, "unreadable.json")
	require.NoError(t, os.WriteFile(unreadable, coverageHelperOriginal, 0o600))
	faultBlockRead(t, unreadable)

	data, err := readRegularMigrationFile(unreadable)
	require.Error(t, err)
	assert.Nil(t, data)

	_, err = loadMigrationJournal(unreadable)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read journal")

	_, err = inspectMigrationFile(unreadable)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read recovery file")
}

func TestStateMigrationHelpers_ValidateJournalRejectsInvalidOperationID(t *testing.T) {
	journal, _ := coverageHelperJournal(t, StateMigrationPhasePrepared)
	require.NoError(t, validateMigrationJournal(journal, journal.JournalPath))
	journal.OperationID = "bad id!"
	assert.ErrorIs(t, validateMigrationJournal(journal, journal.JournalPath), ErrStateMigrationInvalidJournal)
}

func TestStateMigrationHelpers_RemoveFileIfExactFailures(t *testing.T) {
	root := coverageMigrationRoot(t)
	hash, size := stateMigrationHash(coverageHelperDesired), int64(len(coverageHelperDesired))

	err := removeMigrationFileIfExact(filepath.Join(root, "missing", "temp"), hash, size)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe path ancestor")

	dirPath := filepath.Join(root, "temp-dir")
	require.NoError(t, os.Mkdir(dirPath, 0o700))
	err = removeMigrationFileIfExact(dirPath, hash, size)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a regular file")
	assert.DirExists(t, dirPath)

	blockedRoot := coverageMigrationRoot(t)
	blocked := filepath.Join(blockedRoot, "temp")
	require.NoError(t, os.WriteFile(blocked, coverageHelperDesired, 0o600))
	faultBlockRemoval(t, blocked)
	err = removeMigrationFileIfExact(blocked, hash, size)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove temporary file")
	assert.FileExists(t, blocked)
}

func TestStateMigrationHelpers_PreserveSourceFailures(t *testing.T) {
	setHook := func(t *testing.T, target *func(*StateMigrationJournal) error, hook func(*StateMigrationJournal) error) {
		t.Helper()
		previous := *target
		*target = hook
		t.Cleanup(func() { *target = previous })
	}
	writeSource := func(t *testing.T, journal *StateMigrationJournal) {
		t.Helper()
		require.NoError(t, os.WriteFile(journal.SourcePath, coverageHelperOriginal, 0o600))
	}

	t.Run("missing ancestor", func(t *testing.T) {
		err := preserveMigrationSourceExclusively(coverageMissingDirJournal(t, StateMigrationPhasePrepared))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsafe path ancestor")
	})

	t.Run("source is a directory", func(t *testing.T) {
		journal, _ := coverageHelperJournal(t, StateMigrationPhasePrepared)
		require.NoError(t, os.Mkdir(journal.SourcePath, 0o700))
		err := preserveMigrationSourceExclusively(journal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
		assert.NoFileExists(t, journal.BackupPath)
	})

	t.Run("backup is a directory", func(t *testing.T) {
		journal, _ := coverageHelperJournal(t, StateMigrationPhasePrepared)
		writeSource(t, journal)
		require.NoError(t, os.Mkdir(journal.BackupPath, 0o700))
		err := preserveMigrationSourceExclusively(journal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
		assert.Equal(t, coverageHelperOriginal, mustReadFile(t, journal.SourcePath))
	})

	t.Run("link creation blocked", func(t *testing.T) {
		journal, root := coverageHelperJournal(t, StateMigrationPhasePrepared)
		writeSource(t, journal)
		faultBlockCreate(t, root)
		err := preserveMigrationSourceExclusively(journal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exclusive link")
		assert.NoFileExists(t, journal.BackupPath)
		assert.Equal(t, coverageHelperOriginal, mustReadFile(t, journal.SourcePath))
	})

	t.Run("source replaced by directory after link", func(t *testing.T) {
		journal, _ := coverageHelperJournal(t, StateMigrationPhasePrepared)
		writeSource(t, journal)
		setHook(t, &stateMigrationBeforeSourceBackupRemove, func(j *StateMigrationJournal) error {
			require.NoError(t, os.Remove(j.SourcePath))
			return os.Mkdir(j.SourcePath, 0o700)
		})
		err := preserveMigrationSourceExclusively(journal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
		assert.Equal(t, coverageHelperOriginal, mustReadFile(t, journal.BackupPath))
	})

	t.Run("source parent replaced by link after link", func(t *testing.T) {
		journal, root := coverageHelperJournal(t, StateMigrationPhasePrepared)
		work := filepath.Join(root, "work")
		moved := filepath.Join(root, "work-moved")
		require.NoError(t, os.Mkdir(work, 0o700))
		journal.SourcePath = filepath.Join(work, "state.json")
		journal.BackupPath = journal.SourcePath + ".v1"
		journal.TempPath = filepath.Join(work, ".state.json.v2-temp")
		writeSource(t, journal)
		setHook(t, &stateMigrationBeforeSourceBackupRemove, func(*StateMigrationJournal) error {
			if err := os.Rename(work, moved); err != nil {
				return err
			}
			faultDirLink(t, work, moved)
			return nil
		})
		err := preserveMigrationSourceExclusively(journal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsafe path ancestor")
		assert.Equal(t, coverageHelperOriginal, mustReadFile(t, filepath.Join(moved, "state.json")))
	})

	t.Run("final hook error", func(t *testing.T) {
		journal, _ := coverageHelperJournal(t, StateMigrationPhasePrepared)
		writeSource(t, journal)
		hookErr := errors.New("final hook failed")
		setHook(t, &stateMigrationBeforeSourceBackupRemoveFinal, func(*StateMigrationJournal) error { return hookErr })
		err := preserveMigrationSourceExclusively(journal)
		require.ErrorIs(t, err, hookErr)
		assert.Equal(t, coverageHelperOriginal, mustReadFile(t, journal.SourcePath))
		assert.Equal(t, coverageHelperOriginal, mustReadFile(t, journal.BackupPath))
	})

	t.Run("final hook replaces source with directory", func(t *testing.T) {
		journal, _ := coverageHelperJournal(t, StateMigrationPhasePrepared)
		writeSource(t, journal)
		setHook(t, &stateMigrationBeforeSourceBackupRemoveFinal, func(j *StateMigrationJournal) error {
			require.NoError(t, os.Remove(j.SourcePath))
			return os.Mkdir(j.SourcePath, 0o700)
		})
		err := preserveMigrationSourceExclusively(journal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
		assert.DirExists(t, journal.SourcePath)
	})

	t.Run("final source removal blocked", func(t *testing.T) {
		journal, _ := coverageHelperJournal(t, StateMigrationPhasePrepared)
		writeSource(t, journal)
		setHook(t, &stateMigrationBeforeSourceBackupRemoveFinal, func(j *StateMigrationJournal) error {
			faultBlockRemoval(t, j.SourcePath)
			return nil
		})
		err := preserveMigrationSourceExclusively(journal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "remove preserved source")
		assert.Equal(t, coverageHelperOriginal, mustReadFile(t, journal.SourcePath))
		assert.Equal(t, coverageHelperOriginal, mustReadFile(t, journal.BackupPath))
	})
}

func TestStateMigrationHelpers_BackupAfterRenameFailures(t *testing.T) {
	t.Run("missing ancestor", func(t *testing.T) {
		err := validateMigrationBackupAfterRename(coverageMissingDirJournal(t, StateMigrationPhaseBackupRenamed))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsafe path ancestor")
	})

	t.Run("backup is a directory", func(t *testing.T) {
		journal, _ := coverageHelperJournal(t, StateMigrationPhaseBackupRenamed)
		require.NoError(t, os.Mkdir(journal.BackupPath, 0o700))
		err := validateMigrationBackupAfterRename(journal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
	})

	t.Run("backup missing and source is a directory", func(t *testing.T) {
		journal, _ := coverageHelperJournal(t, StateMigrationPhaseBackupRenamed)
		require.NoError(t, os.Mkdir(journal.SourcePath, 0o700))
		err := validateMigrationBackupAfterRename(journal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
	})

	t.Run("backup and source both missing", func(t *testing.T) {
		journal, _ := coverageHelperJournal(t, StateMigrationPhaseBackupRenamed)
		err := validateMigrationBackupAfterRename(journal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "restore changed source")
		assert.NoFileExists(t, journal.SourcePath)
	})
}

func TestStateMigrationHelpers_LinkAndCommitFailures(t *testing.T) {
	root := coverageMigrationRoot(t)
	err := linkMigrationExclusively(filepath.Join(root, "missing", "a"), filepath.Join(root, "b"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe path ancestor")

	tempDir := coverageMigrationRoot(t)
	sourceDir := coverageMigrationRoot(t)
	temp := filepath.Join(tempDir, ".state.json.v2-temp")
	source := filepath.Join(sourceDir, "state.json")
	require.NoError(t, os.WriteFile(temp, coverageHelperDesired, 0o600))
	faultBlockRemoval(t, temp)

	err = commitMigrationTempExclusively(temp, source)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove committed temporary file")
	assert.Equal(t, coverageHelperDesired, mustReadFile(t, source))
	assert.FileExists(t, temp)
}

func TestStateMigrationHelpers_RestoreSourceFromBackupFailures(t *testing.T) {
	t.Run("source cannot be inspected", func(t *testing.T) {
		journal, _ := coverageHelperJournal(t, StateMigrationPhasePrepared)
		journal.SourcePath = faultLstatErrorPath(t, coverageMigrationRoot(t))
		journal.BackupPath = journal.SourcePath + ".v1"
		err := restoreMigrationSourceFromBackup(journal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "inspect path")
	})

	t.Run("backup missing", func(t *testing.T) {
		journal, _ := coverageHelperJournal(t, StateMigrationPhasePrepared)
		err := restoreMigrationSourceFromBackup(journal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secure recovery file")
		assert.NoFileExists(t, journal.SourcePath)
	})

	t.Run("backup is a directory", func(t *testing.T) {
		journal, _ := coverageHelperJournal(t, StateMigrationPhasePrepared)
		require.NoError(t, os.Mkdir(journal.BackupPath, 0o700))
		t.Cleanup(func() { _ = os.Chmod(journal.BackupPath, 0o700) })
		err := restoreMigrationSourceFromBackup(journal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read preserved v1")
		assert.NoFileExists(t, journal.SourcePath)
	})

	t.Run("temporary file creation blocked", func(t *testing.T) {
		journal, root := coverageHelperJournal(t, StateMigrationPhasePrepared)
		require.NoError(t, os.WriteFile(journal.BackupPath, coverageHelperOriginal, 0o600))
		faultBlockCreate(t, root)
		err := restoreMigrationSourceFromBackup(journal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create recovery temporary file")
		assert.NoFileExists(t, journal.SourcePath)
	})
}

func TestStateMigrationHelpers_CommittedMatchRejectsForeignJournalPath(t *testing.T) {
	journal, _ := coverageHelperJournal(t, StateMigrationPhaseCommitted)
	writeStateMigrationJournal(t, journal.JournalPath, *journal)
	otherPath := filepath.Join(filepath.Dir(journal.JournalPath), "other.journal.json")
	require.NoError(t, os.Rename(journal.JournalPath, otherPath))

	matched, err := committedMigrationMatches(otherPath, journal.SourcePath, journal.OperationID, journal.ManifestDigest)
	assert.ErrorIs(t, err, ErrStateMigrationInvalidJournal)
	assert.False(t, matched)
}

func TestStateMigrationHelpers_ValidateCommittedFilesFailures(t *testing.T) {
	err := validateCommittedMigrationFiles(coverageMissingDirJournal(t, StateMigrationPhaseCommitted))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe path ancestor")

	for _, artifact := range []string{"source", "backup", "temp"} {
		t.Run(artifact+" is a directory", func(t *testing.T) {
			journal, _ := coverageHelperJournal(t, StateMigrationPhaseCommitted)
			if artifact != "source" {
				require.NoError(t, os.WriteFile(journal.SourcePath, coverageHelperDesired, 0o600))
			}
			if artifact == "temp" {
				require.NoError(t, os.WriteFile(journal.BackupPath, coverageHelperOriginal, 0o600))
			}
			paths := map[string]string{"source": journal.SourcePath, "backup": journal.BackupPath, "temp": journal.TempPath}
			require.NoError(t, os.Mkdir(paths[artifact], 0o700))

			err := validateCommittedMigrationFiles(journal)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not a regular file")
		})
	}
}

func TestStateMigrationHelpers_InputMatchersReportInspectionErrors(t *testing.T) {
	matchers := map[string]func(*StateMigrationJournal) (bool, error){
		"committed inputs":        migrationCommittedInputsMatch,
		"recovery commit inputs":  migrationRecoveryCommitInputsMatch,
		"rollback inputs":         migrationRollbackInputsMatch,
		"committed state":         migrationCommittedStateMatches,
		"committed journal files": committedMigrationMatchesJournal,
	}
	for name, matcher := range matchers {
		t.Run(name, func(t *testing.T) {
			if name != "committed journal files" {
				matched, err := matcher(coverageMissingDirJournal(t, StateMigrationPhaseCommitted))
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsafe path ancestor")
				assert.False(t, matched)
			}
			for _, artifact := range []string{"source", "backup", "temp"} {
				journal, _ := coverageHelperJournal(t, StateMigrationPhaseCommitted)
				paths := map[string]string{"source": journal.SourcePath, "backup": journal.BackupPath, "temp": journal.TempPath}
				require.NoError(t, os.Mkdir(paths[artifact], 0o700))

				matched, err := matcher(journal)
				require.Error(t, err, artifact)
				assert.Contains(t, err.Error(), "not a regular file", artifact)
				assert.False(t, matched, artifact)
			}
		})
	}
}

// coverageExternalJournalMigration builds a migration fixture whose journal
// lives outside the manifest root so it can be written after signing.
func coverageExternalJournalMigration(t *testing.T) (statePath, journalPath string, manifest *StateManifest, verify func(string, string, *StateManifest) error, now time.Time) {
	t.Helper()
	_, statePath, _, manifest, publicKey, _, now, _ := stateMigrationFixture(t)
	journalPath = filepath.Join(coverageMigrationRoot(t), "migration.journal.json")
	verify = func(statePath, journalPath string, manifest *StateManifest) error {
		return MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-coverage-migration", now)
	}
	return statePath, journalPath, manifest, verify, now
}

func TestStateMigration_MigrateRejectsUnsafeRequests(t *testing.T) {
	t.Run("journal directory missing", func(t *testing.T) {
		statePath, journalPath, manifest, migrate, _ := coverageExternalJournalMigration(t)
		missing := filepath.Join(filepath.Dir(journalPath), "missing", "journal.json")
		err := migrate(statePath, missing, manifest)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsafe path ancestor")
		assert.NoFileExists(t, statePath+".v1")
	})

	t.Run("source missing", func(t *testing.T) {
		statePath, journalPath, manifest, migrate, _ := coverageExternalJournalMigration(t)
		err := migrate(filepath.Join(filepath.Dir(statePath), "absent.json"), journalPath, manifest)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read source")
	})

	t.Run("source outside manifest root", func(t *testing.T) {
		root := coverageMigrationRoot(t)
		manifestRoot := filepath.Join(root, "signed")
		require.NoError(t, os.Mkdir(manifestRoot, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(manifestRoot, "other.json"), coverageHelperOriginal, 0o600))
		statePath := filepath.Join(root, "state.json")
		require.NoError(t, os.WriteFile(statePath, coverageHelperOriginal, 0o600))
		_, _, _, _, publicKey, privateKey, now, _ := stateMigrationFixture(t)
		manifest, err := BuildStateManifest(manifestRoot, "operator", "hub", "nonce-outside", now.Add(5*time.Minute), privateKey, now)
		require.NoError(t, err)

		err = MigrateStateFileV1ToV2(statePath, filepath.Join(root, "journal.json"), manifest, publicKey, "operator", "hub", "op-coverage-migration", now)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "escapes manifest root")
		assert.Equal(t, coverageHelperOriginal, mustReadFile(t, statePath))
	})

	t.Run("journal cannot be inspected", func(t *testing.T) {
		statePath, _, manifest, migrate, _ := coverageExternalJournalMigration(t)
		journalPath := faultLstatErrorPath(t, coverageMigrationRoot(t))
		err := migrate(statePath, journalPath, manifest)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "inspect journal")
		assert.NoFileExists(t, statePath+".v1")
	})

	t.Run("source directory not writable", func(t *testing.T) {
		statePath, journalPath, manifest, migrate, _ := coverageExternalJournalMigration(t)
		original := mustReadFile(t, statePath)
		faultBlockCreate(t, filepath.Dir(statePath))
		err := migrate(statePath, journalPath, manifest)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create temporary file")
		assert.Equal(t, original, mustReadFile(t, statePath))
		assert.NoFileExists(t, journalPath)
	})
}

func TestStateMigration_MigrateValidatesExistingJournal(t *testing.T) {
	t.Run("unsupported journal version", func(t *testing.T) {
		statePath, journalPath, manifest, migrate, now := coverageExternalJournalMigration(t)
		original := mustReadFile(t, statePath)
		digest := stateMigrationManifestDigest(t, manifest)
		journal := coverageMigrationJournal(t, statePath, journalPath, "", digest, original, original, StateMigrationPhasePrepared, now)
		journal.Version = 2
		writeStateMigrationJournal(t, journalPath, journal)

		assert.ErrorIs(t, migrate(statePath, journalPath, manifest), ErrStateMigrationInvalidJournal)
		assert.Equal(t, original, mustReadFile(t, statePath))
	})

	t.Run("journal for another source", func(t *testing.T) {
		statePath, journalPath, manifest, migrate, now := coverageExternalJournalMigration(t)
		original := mustReadFile(t, statePath)
		digest := stateMigrationManifestDigest(t, manifest)
		other := filepath.Join(filepath.Dir(journalPath), "other.json")
		journal := coverageMigrationJournal(t, other, journalPath, "", digest, original, original, StateMigrationPhasePrepared, now)
		writeStateMigrationJournal(t, journalPath, journal)

		err := migrate(statePath, journalPath, manifest)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "journal path mismatch")
	})
}

func TestStateMigration_MigrateCommittedJournalIdempotency(t *testing.T) {
	setup := func(t *testing.T, tempIsDir bool) (statePath, journalPath string, manifest *StateManifest, migrate func() error, current, preserved []byte) {
		t.Helper()
		root := coverageMigrationRoot(t)
		statePath = filepath.Join(root, "state.json")
		current = []byte(`{"schema_version":1,"value":"current"}`)
		preserved = []byte(`{"schema_version":1,"value":"preserved"}`)
		require.NoError(t, os.WriteFile(statePath, current, 0o600))
		require.NoError(t, os.WriteFile(statePath+".v1", preserved, 0o600))
		tempPath := filepath.Join(root, ".state.json.v2-temp")
		if tempIsDir {
			require.NoError(t, os.Mkdir(tempPath, 0o700))
		}
		_, _, _, _, publicKey, privateKey, now, _ := stateMigrationFixture(t)
		var err error
		manifest, err = BuildStateManifest(root, "operator", "hub", "nonce-idempotent", now.Add(5*time.Minute), privateKey, now)
		require.NoError(t, err)
		journalPath = filepath.Join(coverageMigrationRoot(t), "migration.journal.json")
		journal := coverageMigrationJournal(t, statePath, journalPath, tempPath, stateMigrationManifestDigest(t, manifest), preserved, current, StateMigrationPhaseCommitted, now)
		writeStateMigrationJournal(t, journalPath, journal)
		migrate = func() error {
			return MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-coverage-migration", now)
		}
		return statePath, journalPath, manifest, migrate, current, preserved
	}

	t.Run("committed files match journal", func(t *testing.T) {
		statePath, journalPath, _, migrate, current, preserved := setup(t, false)
		before := mustReadFile(t, journalPath)
		require.NoError(t, migrate())
		assert.Equal(t, current, mustReadFile(t, statePath))
		assert.Equal(t, preserved, mustReadFile(t, statePath+".v1"))
		assert.Equal(t, before, mustReadFile(t, journalPath))
	})

	t.Run("committed temporary path is a directory", func(t *testing.T) {
		statePath, _, _, migrate, current, _ := setup(t, true)
		err := migrate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
		assert.Equal(t, current, mustReadFile(t, statePath))
	})
}

func TestStateMigration_MigrateFailsWhenFilesVanishMidway(t *testing.T) {
	t.Run("source removed after prepared journal", func(t *testing.T) {
		root, statePath, journalPath, manifest, publicKey, _, now, _ := stateMigrationFixture(t)
		previous := stateMigrationPersistJournal
		t.Cleanup(func() { stateMigrationPersistJournal = previous })
		stateMigrationPersistJournal = func(journal *StateMigrationJournal) error {
			if err := persistMigrationJournal(journal); err != nil {
				return err
			}
			if journal.Phase == StateMigrationPhasePrepared {
				return os.Remove(statePath)
			}
			return nil
		}

		err := MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-vanish-source", now)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secure source")
		assert.Empty(t, migrationTempFiles(t, root))
		assert.Equal(t, StateMigrationPhasePrepared, readStateMigrationJournal(t, journalPath).Phase)
	})

	t.Run("backup removed before source removal", func(t *testing.T) {
		root, statePath, journalPath, manifest, publicKey, _, now, _ := stateMigrationFixture(t)
		previous := stateMigrationBeforeSourceBackupRemoveFinal
		t.Cleanup(func() { stateMigrationBeforeSourceBackupRemoveFinal = previous })
		stateMigrationBeforeSourceBackupRemoveFinal = func(journal *StateMigrationJournal) error {
			return os.Remove(journal.BackupPath)
		}

		err := MigrateStateFileV1ToV2(statePath, journalPath, manifest, publicKey, "operator", "hub", "op-vanish-backup", now)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secure v1 backup")
		temps := migrationTempFiles(t, root)
		require.Len(t, temps, 1)
		assert.True(t, strings.Contains(temps[0], ".v2-"))
		assert.Equal(t, StateMigrationPhasePrepared, readStateMigrationJournal(t, journalPath).Phase)
	})
}

// coverageRecoveryCase writes recovery artifacts in a dedicated root with the
// journal kept in a separate directory.
type coverageRecoveryCase struct {
	journal *StateMigrationJournal
	root    string
	now     time.Time
}

func newCoverageRecoveryCase(t *testing.T, phase StateMigrationPhase, source, backup, temp []byte) coverageRecoveryCase {
	t.Helper()
	journal, root := coverageHelperJournal(t, phase)
	for path, content := range map[string][]byte{journal.SourcePath: source, journal.BackupPath: backup, journal.TempPath: temp} {
		if content != nil {
			require.NoError(t, os.WriteFile(path, content, 0o600))
		}
	}
	writeStateMigrationJournal(t, journal.JournalPath, *journal)
	return coverageRecoveryCase{journal: journal, root: root, now: journal.CreatedAt.Add(time.Minute)}
}

func (c coverageRecoveryCase) recover() error {
	return RecoverStateMigration(c.journal.JournalPath, c.now)
}

func TestStateMigration_RecoverRejectsRelativeJournalPath(t *testing.T) {
	err := RecoverStateMigration("migration.journal.json", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid path")
}

func TestStateMigration_RecoverReportsFilesystemFailures(t *testing.T) {
	original, desired := coverageHelperOriginal, coverageHelperDesired

	t.Run("prepared rollback cannot remove temporary file", func(t *testing.T) {
		c := newCoverageRecoveryCase(t, StateMigrationPhasePrepared, original, nil, desired)
		faultBlockRemoval(t, c.journal.TempPath)
		err := c.recover()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "remove temporary file")
		assert.FileExists(t, c.journal.TempPath)
		assert.Equal(t, StateMigrationPhasePrepared, readStateMigrationJournal(t, c.journal.JournalPath).Phase)
	})

	t.Run("prepared restore cannot create source", func(t *testing.T) {
		c := newCoverageRecoveryCase(t, StateMigrationPhasePrepared, nil, original, desired)
		faultBlockCreate(t, c.root)
		err := c.recover()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create recovery temporary file")
		assert.NoFileExists(t, c.journal.SourcePath)
		assert.Equal(t, StateMigrationPhasePrepared, readStateMigrationJournal(t, c.journal.JournalPath).Phase)
	})

	t.Run("backup renamed cannot remove temporary file", func(t *testing.T) {
		c := newCoverageRecoveryCase(t, StateMigrationPhaseBackupRenamed, desired, original, desired)
		faultBlockRemoval(t, c.journal.TempPath)
		err := c.recover()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "remove temporary file")
		assert.FileExists(t, c.journal.TempPath)
		assert.Equal(t, StateMigrationPhaseBackupRenamed, readStateMigrationJournal(t, c.journal.JournalPath).Phase)
	})

	t.Run("backup renamed cannot link committed source", func(t *testing.T) {
		c := newCoverageRecoveryCase(t, StateMigrationPhaseBackupRenamed, nil, original, desired)
		faultBlockCreate(t, c.root)
		err := c.recover()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "recover v2 commit")
		assert.NoFileExists(t, c.journal.SourcePath)
		assert.Equal(t, desired, mustReadFile(t, c.journal.TempPath))
	})
}
