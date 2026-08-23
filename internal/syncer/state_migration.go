package syncer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const StateMigrationJournalVersion = 1

type StateMigrationPhase string
type StateMigrationJournalPhase = StateMigrationPhase

const (
	StateMigrationPhasePrepared          StateMigrationPhase = "prepared"
	StateMigrationPhaseBackupRenamed     StateMigrationPhase = "backup_renamed"
	StateMigrationPhaseCommitted         StateMigrationPhase = "committed"
	StateMigrationPhaseNeedsReconciliation StateMigrationPhase = "needs_reconciliation"

	// StateMigrationJournalPhase* aliases keep phase names discoverable without
	// duplicating the serialized values.
	StateMigrationJournalPhasePrepared          = StateMigrationPhasePrepared
	StateMigrationJournalPhaseBackupRenamed     = StateMigrationPhaseBackupRenamed
	StateMigrationJournalPhaseCommitted         = StateMigrationPhaseCommitted
	StateMigrationJournalPhaseNeedsReconciliation = StateMigrationPhaseNeedsReconciliation
)

var (
	ErrStateMigrationNeedsReconciliation = errors.New("state migration needs reconciliation")
	ErrStateMigrationInvalidJournal      = errors.New("state migration journal is invalid")

	stateMigrationPersistJournal      = persistMigrationJournal
	stateMigrationBeforeRecoveryCommit func(*StateMigrationJournal) error
)

// StateMigrationJournal contains only metadata needed to recover one local
// state-file migration. It intentionally has no state-file values.
type StateMigrationJournal struct {
	Version        int                 `json:"version"`
	OperationID    string              `json:"operation_id"`
	ManifestDigest string              `json:"manifest_digest"`
	SourcePath     string              `json:"source_path"`
	BackupPath     string              `json:"backup_path"`
	TempPath       string              `json:"temp_path"`
	JournalPath    string              `json:"journal_path"`
	SourceHash     string              `json:"source_hash"`
	SourceSize     int64               `json:"source_size"`
	DesiredHash    string              `json:"desired_hash"`
	DesiredSize    int64               `json:"desired_size"`
	Phase          StateMigrationPhase `json:"phase"`
	CreatedAt      time.Time           `json:"created_at"`
	UpdatedAt      time.Time           `json:"updated_at"`
}

// MigrateStateFileV1ToV2 upgrades one state JSON object with metadata signed
// by a previously verified StateManifest. Every filesystem transition is
// journaled and the v1 bytes remain at statePath+.v1 forever.
func MigrateStateFileV1ToV2(
	statePath, journalPath string,
	manifest *StateManifest,
	publicKey ed25519.PublicKey,
	expectedRole, expectedAudience, operationID string,
	now time.Time,
) error {
	syncStateSaveMu.Lock()
	defer syncStateSaveMu.Unlock()
	manifestErr := VerifyStateManifest(manifest, manifestSourceRoot(manifest), expectedRole, expectedAudience, publicKey, now)
	manifestDigest, digestErr := migrationManifestDigest(manifest)
	if manifestErr != nil {
		if digestErr == nil {
			if idempotent, err := committedMigrationMatches(journalPath, statePath, operationID, manifestDigest); err == nil && idempotent {
				return nil
			}
		}
		return manifestErr
	}
	if digestErr != nil {
		return digestErr
	}
	if err := validateMigrationRequestPaths(statePath, journalPath); err != nil {
		return err
	}
	if err := validateStateMigrationOperationID(operationID); err != nil {
		return err
	}

	raw, err := readRegularMigrationFile(statePath)
	if err != nil {
		return fmt.Errorf("state migration: read source: %w", err)
	}
	row, err := stateManifestRowForPath(manifest, statePath)
	if err != nil {
		return err
	}
	if int64(len(raw)) != row.Size || migrationHash(raw) != row.SHA256 {
		return errors.New("state migration: source hash or size does not match manifest")
	}

	object, err := decodeV1StateObject(raw)
	if err != nil {
		return err
	}
	object["schema_version"] = json.RawMessage(`2`)
	manifestDigestJSON, err := json.Marshal(manifestDigest)
	if err != nil {
		return errors.New("state migration: encode manifest digest")
	}
	object["manifest_digest"] = manifestDigestJSON
	desired, err := json.Marshal(object)
	if err != nil {
		return errors.New("state migration: encode v2 state")
	}

	backupPath := statePath + ".v1"
	if err := validateMigrationPaths(statePath, backupPath, "", journalPath); err != nil {
		return err
	}
	if existing, err := loadMigrationJournalIfPresent(journalPath); err != nil {
		return err
	} else if existing != nil {
		if err := validateMigrationJournal(existing, journalPath); err != nil {
			return err
		}
		if existing.OperationID != operationID {
			return errors.New("state migration: journal operation mismatch")
		}
		if existing.ManifestDigest != manifestDigest {
			return errors.New("state migration: journal manifest mismatch")
		}
		if existing.SourcePath != statePath || existing.BackupPath != backupPath {
			return errors.New("state migration: journal path mismatch")
		}
		if existing.Phase == StateMigrationPhaseCommitted {
			matched, err := committedMigrationMatchesJournal(existing)
			if err != nil {
				return err
			}
			if matched {
				return nil
			}
		}
		return errors.New("state migration: existing journal requires recovery")
	}
	if exists, err := migrationPathExists(backupPath); err != nil {
		return err
	} else if exists {
		return errors.New("state migration: v1 backup already exists")
	}

	tempFile, err := os.CreateTemp(filepath.Dir(statePath), "."+filepath.Base(statePath)+".v2-")
	if err != nil {
		return fmt.Errorf("state migration: create temporary file: %w", err)
	}
	tempPath := tempFile.Name()
	removeTemp := true
	defer func() {
		_ = tempFile.Close()
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if err := tempFile.Chmod(0o600); err != nil {
		return fmt.Errorf("state migration: chmod temporary file: %w", err)
	}
	if n, err := tempFile.Write(desired); err != nil {
		return fmt.Errorf("state migration: write temporary file: %w", err)
	} else if n != len(desired) {
		return errors.New("state migration: short write to temporary file")
	}
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("state migration: sync temporary file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("state migration: close temporary file: %w", err)
	}

	journal := &StateMigrationJournal{
		Version:        StateMigrationJournalVersion,
		OperationID:    operationID,
		ManifestDigest: manifestDigest,
		SourcePath:     statePath,
		BackupPath:     backupPath,
		TempPath:       tempPath,
		JournalPath:    journalPath,
		SourceHash:     migrationHash(raw),
		SourceSize:     int64(len(raw)),
		DesiredHash:    migrationHash(desired),
		DesiredSize:    int64(len(desired)),
		Phase:          StateMigrationPhasePrepared,
		CreatedAt:      now.UTC(),
		UpdatedAt:      now.UTC(),
	}
	if err := stateMigrationPersistJournal(journal); err != nil {
		return err
	}

	if err := os.Chmod(statePath, 0o600); err != nil {
		return fmt.Errorf("state migration: secure source: %w", err)
	}
	if err := os.Rename(statePath, backupPath); err != nil {
		return fmt.Errorf("state migration: preserve v1 backup: %w", err)
	}
	removeTemp = false
	if err := os.Chmod(backupPath, 0o600); err != nil {
		return fmt.Errorf("state migration: secure v1 backup: %w", err)
	}
	journal.Phase = StateMigrationPhaseBackupRenamed
	journal.UpdatedAt = now.UTC()
	if err := stateMigrationPersistJournal(journal); err != nil {
		return err
	}
	if err := validateMigrationBackupAfterRename(journal); err != nil {
		return err
	}

	if err := commitMigrationTempExclusively(tempPath, statePath); err != nil {
		return fmt.Errorf("state migration: commit v2 state: %w", err)
	}
	removeTemp = false
	journal.Phase = StateMigrationPhaseCommitted
	journal.UpdatedAt = now.UTC()
	if err := stateMigrationPersistJournal(journal); err != nil {
		return err
	}
	return nil
}

// RecoverStateMigration deterministically resumes or rolls back the exact
// paths and hashes recorded in a journal. It never guesses when the on-disk
// state is ambiguous.
func RecoverStateMigration(journalPath string, now time.Time) error {
	syncStateSaveMu.Lock()
	defer syncStateSaveMu.Unlock()
	if err := validateMigrationPath(journalPath); err != nil {
		return err
	}
	journal, err := loadMigrationJournal(journalPath)
	if err != nil {
		return err
	}
	if err := validateMigrationJournal(journal, journalPath); err != nil {
		return err
	}
	if journal.Phase == StateMigrationPhaseNeedsReconciliation {
		return ErrStateMigrationNeedsReconciliation
	}

	source, err := inspectMigrationFile(journal.SourcePath)
	if err != nil {
		return err
	}
	backup, err := inspectMigrationFile(journal.BackupPath)
	if err != nil {
		return err
	}
	temp, err := inspectMigrationFile(journal.TempPath)
	if err != nil {
		return err
	}
	if stateMigrationBeforeRecoveryCommit != nil {
		if err := stateMigrationBeforeRecoveryCommit(journal); err != nil {
			return err
		}
	}
	sourceOK := source.matches(journal.SourceHash, journal.SourceSize)
	backupOK := backup.matches(journal.SourceHash, journal.SourceSize)
	desiredOK := temp.matches(journal.DesiredHash, journal.DesiredSize)
	committedOK := source.matches(journal.DesiredHash, journal.DesiredSize) && backupOK && !temp.exists

	switch journal.Phase {
	case StateMigrationPhasePrepared:
		if committedOK {
			if err := secureMigrationFile(journal.SourcePath); err != nil {
				return err
			}
			if err := secureMigrationFile(journal.BackupPath); err != nil {
				return err
			}
			journal.Phase = StateMigrationPhaseCommitted
			journal.UpdatedAt = now.UTC()
			return persistMigrationJournal(journal)
		}
		if sourceOK && !backup.exists && desiredOK {
			if err := secureMigrationFile(journal.SourcePath); err != nil {
				return err
			}
			if err := removeMigrationFileIfExact(journal.TempPath, journal.DesiredHash, journal.DesiredSize); err != nil {
				return err
			}
			return markMigrationNeedsReconciliation(journal, now)
		}
		if !source.exists && backupOK && desiredOK {
			if err := restoreMigrationSourceFromBackup(journal); err != nil {
				return err
			}
			if err := removeMigrationFileIfExact(journal.TempPath, journal.DesiredHash, journal.DesiredSize); err != nil {
				return err
			}
			return markMigrationNeedsReconciliation(journal, now)
		}
		return markMigrationNeedsReconciliation(journal, now)

	case StateMigrationPhaseBackupRenamed:
		if committedOK {
			if err := secureMigrationFile(journal.SourcePath); err != nil {
				return err
			}
			if err := secureMigrationFile(journal.BackupPath); err != nil {
				return err
			}
			journal.Phase = StateMigrationPhaseCommitted
			journal.UpdatedAt = now.UTC()
			return persistMigrationJournal(journal)
		}
		if source.matches(journal.DesiredHash, journal.DesiredSize) && backupOK && desiredOK {
			if err := secureMigrationFile(journal.SourcePath); err != nil {
				return err
			}
			if err := secureMigrationFile(journal.BackupPath); err != nil {
				return err
			}
			if err := removeMigrationFileIfExact(journal.TempPath, journal.DesiredHash, journal.DesiredSize); err != nil {
				return err
			}
			journal.Phase = StateMigrationPhaseCommitted
			journal.UpdatedAt = now.UTC()
			return persistMigrationJournal(journal)
		}
		if !source.exists && backupOK && desiredOK {
			if err := secureMigrationFile(journal.BackupPath); err != nil {
				return err
			}
			if err := commitMigrationTempExclusively(journal.TempPath, journal.SourcePath); err != nil {
				return fmt.Errorf("state migration: recover v2 commit: %w", err)
			}
			journal.Phase = StateMigrationPhaseCommitted
			journal.UpdatedAt = now.UTC()
			return persistMigrationJournal(journal)
		}
		return markMigrationNeedsReconciliation(journal, now)

	case StateMigrationPhaseCommitted:
		if committedOK {
			if err := secureMigrationFile(journal.SourcePath); err != nil {
				return err
			}
			if err := secureMigrationFile(journal.BackupPath); err != nil {
				return err
			}
			return nil
		}
		return markMigrationNeedsReconciliation(journal, now)
	default:
		return markMigrationNeedsReconciliation(journal, now)
	}
}

func manifestSourceRoot(manifest *StateManifest) string {
	if manifest == nil {
		return ""
	}
	return manifest.SourceRoot
}

func migrationManifestDigest(manifest *StateManifest) (string, error) {
	canonical, err := manifest.CanonicalSigningBytes()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func migrationHash(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func validateStateMigrationOperationID(operationID string) error {
	if operationID == "" || operationID == "." || operationID == ".." || len(operationID) > 128 || strings.TrimSpace(operationID) != operationID {
		return errors.New("state migration: invalid operation id")
	}
	for _, r := range operationID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return errors.New("state migration: invalid operation id")
	}
	return nil
}

func validateMigrationPath(path string) error {
	if path == "" || strings.ContainsRune(path, 0) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("state migration: invalid path")
	}
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == "." || part == ".." {
			return errors.New("state migration: path traversal rejected")
		}
	}
	return nil
}

func validateMigrationRequestPaths(statePath, journalPath string) error {
	if err := validateMigrationPath(statePath); err != nil {
		return err
	}
	if err := validateMigrationPath(journalPath); err != nil {
		return err
	}
	return validateMigrationPaths(statePath, statePath+".v1", "", journalPath)
}

func validateMigrationPaths(sourcePath, backupPath, tempPath, journalPath string) error {
	for _, path := range []string{sourcePath, backupPath, journalPath} {
		if err := validateMigrationPath(path); err != nil {
			return err
		}
	}
	if backupPath != sourcePath+".v1" {
		return errors.New("state migration: invalid backup path")
	}
	if tempPath != "" {
		if err := validateMigrationPath(tempPath); err != nil {
			return err
		}
		if filepath.Dir(tempPath) != filepath.Dir(sourcePath) {
			return errors.New("state migration: temporary path escapes source directory")
		}
		if tempPath == sourcePath || tempPath == backupPath {
			return errors.New("state migration: temporary path aliases state path")
		}
	}
	if journalPath == sourcePath || journalPath == backupPath || journalPath == tempPath {
		return errors.New("state migration: journal path aliases state path")
	}
	return nil
}

func stateManifestRowForPath(manifest *StateManifest, statePath string) (StateManifestFile, error) {
	root, err := canonicalizeStateManifestRoot(manifest.SourceRoot)
	if err != nil {
		return StateManifestFile{}, err
	}
	if filepath.Clean(statePath) != statePath {
		return StateManifestFile{}, errors.New("state migration: invalid source path")
	}
	rel, err := filepath.Rel(root, statePath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return StateManifestFile{}, errors.New("state migration: source path escapes manifest root")
	}
	rel = filepath.ToSlash(rel)
	for _, row := range manifest.Files {
		if row.Path == rel {
			return row, nil
		}
	}
	return StateManifestFile{}, errors.New("state migration: source file is not in manifest")
}

func decodeV1StateObject(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil {
		return nil, errors.New("state migration: source is not valid v1 JSON object")
	}
	if object == nil {
		return nil, errors.New("state migration: source is not a v1 JSON object")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("state migration: source contains trailing data")
	}
	if schema, ok := object["schema_version"]; ok {
		var version int
		if err := json.Unmarshal(schema, &version); err != nil || version != 1 {
			return nil, errors.New("state migration: source is not v1")
		}
	}
	return object, nil
}

func migrationPathExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("state migration: inspect path: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("state migration: path is not a regular file")
	}
	return true, nil
}

func readRegularMigrationFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("state migration: source is not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func persistMigrationJournal(journal *StateMigrationJournal) error {
	if err := validateMigrationJournal(journal, journal.JournalPath); err != nil {
		return err
	}
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return errors.New("state migration: encode journal")
	}
	file, err := os.CreateTemp(filepath.Dir(journal.JournalPath), "."+filepath.Base(journal.JournalPath)+".tmp-")
	if err != nil {
		return fmt.Errorf("state migration: create journal temporary file: %w", err)
	}
	tempPath := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(tempPath)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("state migration: chmod journal temporary file: %w", err)
	}
	if n, err := file.Write(data); err != nil {
		return fmt.Errorf("state migration: write journal: %w", err)
	} else if n != len(data) {
		return errors.New("state migration: short journal write")
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("state migration: sync journal: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("state migration: close journal: %w", err)
	}
	if err := os.Rename(tempPath, journal.JournalPath); err != nil {
		return fmt.Errorf("state migration: commit journal: %w", err)
	}
	keep = true
	return nil
}

func loadMigrationJournal(path string) (*StateMigrationJournal, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("state migration: read journal: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, ErrStateMigrationInvalidJournal
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("state migration: read journal: %w", err)
	}
	var journal StateMigrationJournal
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return nil, ErrStateMigrationInvalidJournal
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, ErrStateMigrationInvalidJournal
	}
	return &journal, nil
}

func loadMigrationJournalIfPresent(path string) (*StateMigrationJournal, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("state migration: inspect journal: %w", err)
	}
	return loadMigrationJournal(path)
}

func validateMigrationJournal(journal *StateMigrationJournal, expectedPath string) error {
	if journal == nil {
		return ErrStateMigrationInvalidJournal
	}
	if journal.Version != StateMigrationJournalVersion || journal.OperationID == "" || journal.ManifestDigest == "" {
		return ErrStateMigrationInvalidJournal
	}
	if err := validateStateMigrationOperationID(journal.OperationID); err != nil {
		return ErrStateMigrationInvalidJournal
	}
	if !validStateMigrationDigest(journal.ManifestDigest) || !validStateMigrationHash(journal.SourceHash) || !validStateMigrationHash(journal.DesiredHash) {
		return ErrStateMigrationInvalidJournal
	}
	if journal.SourceSize < 0 || journal.DesiredSize < 0 || journal.CreatedAt.IsZero() || journal.UpdatedAt.IsZero() {
		return ErrStateMigrationInvalidJournal
	}
	if journal.Phase != StateMigrationPhasePrepared && journal.Phase != StateMigrationPhaseBackupRenamed && journal.Phase != StateMigrationPhaseCommitted && journal.Phase != StateMigrationPhaseNeedsReconciliation {
		return ErrStateMigrationInvalidJournal
	}
	if err := validateMigrationPaths(journal.SourcePath, journal.BackupPath, journal.TempPath, journal.JournalPath); err != nil {
		return ErrStateMigrationInvalidJournal
	}
	if expectedPath != "" && journal.JournalPath != expectedPath {
		return ErrStateMigrationInvalidJournal
	}
	return nil
}

func validStateMigrationHash(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validStateMigrationDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validStateMigrationHash(strings.TrimPrefix(value, "sha256:"))
}

type migrationFileInfo struct {
	exists bool
	size   int64
	hash   string
}

func inspectMigrationFile(path string) (migrationFileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return migrationFileInfo{}, nil
	}
	if err != nil {
		return migrationFileInfo{}, fmt.Errorf("state migration: inspect file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return migrationFileInfo{}, errors.New("state migration: recovery path is not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return migrationFileInfo{}, fmt.Errorf("state migration: read recovery file: %w", err)
	}
	return migrationFileInfo{exists: true, size: int64(len(data)), hash: migrationHash(data)}, nil
}

func (info migrationFileInfo) matches(hash string, size int64) bool {
	return info.exists && info.size == size && info.hash == hash
}

func removeMigrationFileIfExact(path, expectedHash string, expectedSize int64) error {
	info, err := inspectMigrationFile(path)
	if err != nil {
		return err
	}
	if !info.matches(expectedHash, expectedSize) {
		return errors.New("state migration: temporary file changed during recovery")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("state migration: remove temporary file: %w", err)
	}
	return nil
}
func validateMigrationBackupAfterRename(journal *StateMigrationJournal) error {
	backup, err := inspectMigrationFile(journal.BackupPath)
	if err != nil {
		return err
	}
	if backup.matches(journal.SourceHash, journal.SourceSize) {
		return nil
	}
	if exists, err := migrationPathExists(journal.SourcePath); err != nil {
		return err
	} else if exists {
		return errors.New("state migration: source or backup changed during migration")
	}
	if err := linkMigrationExclusively(journal.BackupPath, journal.SourcePath); err != nil {
		return fmt.Errorf("state migration: restore changed source: %w", err)
	}
	if err := removeMigrationFileIfExact(journal.TempPath, journal.DesiredHash, journal.DesiredSize); err != nil {
		return err
	}
	return errors.New("state migration: source or backup changed during migration")
}

func linkMigrationExclusively(sourcePath, destinationPath string) error {
	if err := os.Link(sourcePath, destinationPath); err != nil {
		return fmt.Errorf("state migration: exclusive link: %w", err)
	}
	return nil
}

func commitMigrationTempExclusively(tempPath, sourcePath string) error {
	if err := linkMigrationExclusively(tempPath, sourcePath); err != nil {
		return err
	}
	if err := os.Remove(tempPath); err != nil {
		return fmt.Errorf("state migration: remove committed temporary file: %w", err)
	}
	return nil
}

func secureMigrationFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("state migration: secure recovery file: %w", err)
	}
	return nil
}

func restoreMigrationSourceFromBackup(journal *StateMigrationJournal) error {
	if exists, err := migrationPathExists(journal.SourcePath); err != nil {
		return err
	} else if exists {
		return errors.New("state migration: source appeared during recovery")
	}
	if err := secureMigrationFile(journal.BackupPath); err != nil {
		return err
	}
	backup, err := readRegularMigrationFile(journal.BackupPath)
	if err != nil {
		return fmt.Errorf("state migration: read preserved v1: %w", err)
	}
	if int64(len(backup)) != journal.SourceSize || migrationHash(backup) != journal.SourceHash {
		return errors.New("state migration: preserved v1 hash or size mismatch")
	}
	file, err := os.CreateTemp(filepath.Dir(journal.SourcePath), "."+filepath.Base(journal.SourcePath)+".restore-")
	if err != nil {
		return fmt.Errorf("state migration: create recovery temporary file: %w", err)
	}
	tempPath := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(tempPath)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("state migration: chmod recovery temporary file: %w", err)
	}
	if n, err := file.Write(backup); err != nil {
		return fmt.Errorf("state migration: write recovery temporary file: %w", err)
	} else if n != len(backup) {
		return errors.New("state migration: short recovery write")
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("state migration: sync recovery temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("state migration: close recovery temporary file: %w", err)
	}
	if err := commitMigrationTempExclusively(tempPath, journal.SourcePath); err != nil {
		return fmt.Errorf("state migration: restore preserved v1: %w", err)
	}
	keep = true
	return nil
}


func markMigrationNeedsReconciliation(journal *StateMigrationJournal, now time.Time) error {
	journal.Phase = StateMigrationPhaseNeedsReconciliation
	journal.UpdatedAt = now.UTC()
	if err := persistMigrationJournal(journal); err != nil {
		return err
	}
	return ErrStateMigrationNeedsReconciliation
}

func committedMigrationMatches(path, statePath, operationID, manifestDigest string) (bool, error) {
	journal, err := loadMigrationJournalIfPresent(path)
	if err != nil || journal == nil {
		return false, err
	}
	if err := validateMigrationJournal(journal, path); err != nil {
		return false, err
	}
	if journal.OperationID != operationID || journal.ManifestDigest != manifestDigest || journal.SourcePath != statePath || journal.Phase != StateMigrationPhaseCommitted {
		return false, nil
	}
	return committedMigrationMatchesJournal(journal)
}

func committedMigrationMatchesJournal(journal *StateMigrationJournal) (bool, error) {
	if journal == nil || journal.Phase != StateMigrationPhaseCommitted {
		return false, nil
	}
	source, err := inspectMigrationFile(journal.SourcePath)
	if err != nil {
		return false, err
	}
	backup, err := inspectMigrationFile(journal.BackupPath)
	if err != nil {
		return false, err
	}
	temp, err := inspectMigrationFile(journal.TempPath)
	if err != nil {
		return false, err
	}
	return source.matches(journal.DesiredHash, journal.DesiredSize) && backup.matches(journal.SourceHash, journal.SourceSize) && !temp.exists, nil
}
