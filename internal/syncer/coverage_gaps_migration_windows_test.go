//go:build windows

package syncer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// Windows lets an ACL deny FILE_WRITE_ATTRIBUTES while the owner keeps read
// access, so these recovery steps can observe a chmod failure on a file that
// still hashes correctly.
func TestStateMigration_RecoverReportsSecureFailuresWindows(t *testing.T) {
	original, desired := coverageHelperOriginal, coverageHelperDesired
	cases := []struct {
		name                 string
		phase                StateMigrationPhase
		source, backup, temp []byte
		blockSource          bool
	}{
		{"prepared committed source", StateMigrationPhasePrepared, desired, original, nil, true},
		{"prepared committed backup", StateMigrationPhasePrepared, desired, original, nil, false},
		{"prepared rollback source", StateMigrationPhasePrepared, original, nil, desired, true},
		{"backup renamed committed source", StateMigrationPhaseBackupRenamed, desired, original, nil, true},
		{"backup renamed committed backup", StateMigrationPhaseBackupRenamed, desired, original, nil, false},
		{"backup renamed leftover temp source", StateMigrationPhaseBackupRenamed, desired, original, desired, true},
		{"backup renamed leftover temp backup", StateMigrationPhaseBackupRenamed, desired, original, desired, false},
		{"backup renamed missing source backup", StateMigrationPhaseBackupRenamed, nil, original, desired, false},
		{"committed source", StateMigrationPhaseCommitted, desired, original, nil, true},
		{"committed backup", StateMigrationPhaseCommitted, desired, original, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCoverageRecoveryCase(t, tc.phase, tc.source, tc.backup, tc.temp)
			if tc.blockSource {
				faultBlockChmod(t, c.journal.SourcePath)
			} else {
				faultBlockChmod(t, c.journal.BackupPath)
			}

			err := c.recover()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "secure recovery file")
			assert.Equal(t, tc.phase, readStateMigrationJournal(t, c.journal.JournalPath).Phase)
			if tc.source != nil {
				assert.Equal(t, tc.source, mustReadFile(t, c.journal.SourcePath))
			}
		})
	}
}

// A handle without FILE_SHARE_DELETE lets the restore succeed but keeps the
// temporary file from being removed afterwards.
func TestStateMigration_RecoverPreparedRestoreKeepsLockedTemporaryFileWindows(t *testing.T) {
	c := newCoverageRecoveryCase(t, StateMigrationPhasePrepared, nil, coverageHelperOriginal, coverageHelperDesired)
	faultOpenHandle(t, c.journal.TempPath, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)

	err := c.recover()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove temporary file")
	assert.Equal(t, coverageHelperOriginal, mustReadFile(t, c.journal.SourcePath))
	assert.Equal(t, coverageHelperDesired, mustReadFile(t, c.journal.TempPath))
	assert.Equal(t, StateMigrationPhasePrepared, readStateMigrationJournal(t, c.journal.JournalPath).Phase)
}
