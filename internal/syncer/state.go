package syncer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/n24q02m/skret/internal/provider"
)

// SyncState tracks per-secret SHA256(value) hashes for drift detection.
// Persisted at ~/.skret/sync-state/<target>-<sanitized-id>.json.
type SyncState struct {
	Target  string            `json:"target"`
	ID      string            `json:"id"`
	Hashes  map[string]string `json:"hashes"`
	Updated time.Time         `json:"updated"`
}

// StatePathFor returns the on-disk path for the given target+id.
// Exposed for testing; production code uses LoadSyncState/SaveSyncState.
func StatePathFor(target, id string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("user home dir: %w", err)
	}
	return filepath.Join(home, ".skret", "sync-state", fmt.Sprintf("%s-%s.json", sanitizeID(target), sanitizeID(id))), nil
}

// idReplacer is used by sanitizeID to neutralize dangerous characters.
// Hoisted to package level to avoid redundant initialization allocations.
var idReplacer = strings.NewReplacer(
	"..", "_",
	"/", "-",
	":", "-",
	`\`, "-",
	" ", "_",
	"\x00", "_",
)

// sanitizeID neutralizes characters that could escape the sync-state
// directory (path traversal) or break the on-disk file-name scheme.
// "..", path separators and NULs are collapsed to inert runes.
func sanitizeID(id string) string {
	out := idReplacer.Replace(id)
	if out == "" || out == "." {
		return "_"
	}
	return out
}

// LoadSyncState reads the state file for target+id, returning an empty
// state if the file does not exist (first-run case).
func LoadSyncState(target, id string) (*SyncState, error) {
	path, err := StatePathFor(target, id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &SyncState{Target: target, ID: id, Hashes: map[string]string{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read sync state %q: %w", path, err)
	}
	var s SyncState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse sync state %q: %w", path, err)
	}
	if s.Hashes == nil {
		s.Hashes = map[string]string{}
	}
	s.Target = target
	s.ID = id
	return &s, nil
}

// SaveSyncState writes the state atomically. The directory is created with
// 0700 and the file with 0600 so secret-name presence is owner-only readable.
func SaveSyncState(s *SyncState) error {
	path, err := StatePathFor(s.Target, s.ID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create sync state dir: %w", err)
	}
	s.Updated = time.Now().UTC()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sync state: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write sync state %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename sync state %q -> %q: %w", tmp, path, err)
	}
	return nil
}

// hashSecret returns hex-encoded SHA256 of the secret value.
func hashSecret(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

// FilterUnchanged returns only the secrets whose hash differs from the state.
// Secrets not present in the state are included (treated as new).
func (s *SyncState) FilterUnchanged(secrets []*provider.Secret) []*provider.Secret {
	out := make([]*provider.Secret, 0, len(secrets))
	for _, sec := range secrets {
		if s.Hashes[sec.Key] != hashSecret(sec.Value) {
			out = append(out, sec)
		}
	}
	return out
}

// Update records the hashes of the given secrets in-place.
func (s *SyncState) Update(secrets []*provider.Secret) {
	if s.Hashes == nil {
		s.Hashes = map[string]string{}
	}
	for _, sec := range secrets {
		s.Hashes[sec.Key] = hashSecret(sec.Value)
	}
}
