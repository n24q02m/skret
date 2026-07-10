package syncer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/n24q02m/skret/internal/provider"
)

// Manifest is the names-only inventory published to the vault hub. It never
// contains secret values — only salted fingerprints, names, and drift status.
type Manifest struct {
	Namespace   string        `json:"namespace"`
	Env         string        `json:"env"`
	GeneratedAt time.Time     `json:"generated_at"`
	Keys        []ManifestKey `json:"keys"`
}

type ManifestKey struct {
	Name        string                    `json:"name"`
	Fingerprint string                    `json:"fingerprint"`
	UpdatedAt   time.Time                 `json:"updated_at"`
	Targets     map[string]ManifestTarget `json:"targets"`
}

type ManifestTarget struct {
	Present bool   `json:"present"`
	Status  string `json:"status"` // in-sync | drift | missing
}

// Fingerprint returns salted sha256[:8] of a value. Salt keeps it opaque to
// cross-deployment rainbow tables while staying stable within one deployment.
func Fingerprint(salt []byte, value string) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))[:8]
}

// LoadDeploySalt reads (or first-run creates) a 16-byte deployment salt at
// ~/.skret/hub-salt with 0600. The salt never leaves the machine.
func LoadDeploySalt() ([]byte, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("user home dir: %w", err)
	}
	path := filepath.Join(home, ".skret", "hub-salt")
	data, err := os.ReadFile(path)
	if err == nil && len(data) >= 16 {
		return data, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read hub salt %q: %w", path, err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate hub salt: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create skret dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, salt, 0o600); err != nil {
		return nil, fmt.Errorf("write hub salt %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("rename hub salt %q -> %q: %w", tmp, path, err)
	}
	return salt, nil
}

// BuildManifest computes per-key fingerprint + per-target drift from the
// current SSM secrets and each target's last-synced SyncState. GeneratedAt
// is left zero here — the caller (hub push) stamps it once, so the manifest
// timestamp is set exactly one place.
func BuildManifest(ns, env string, salt []byte, secrets []*provider.Secret, states map[string]*SyncState) *Manifest {
	m := &Manifest{Namespace: ns, Env: env, Keys: make([]ManifestKey, 0, len(secrets))}
	for _, s := range secrets {
		cur := hashSecret(s.Value)
		targets := map[string]ManifestTarget{}
		for tname, st := range states {
			if st == nil {
				targets[tname] = ManifestTarget{Present: false, Status: "missing"}
				continue
			}
			last, ok := st.Hashes[s.Key]
			switch {
			case !ok:
				targets[tname] = ManifestTarget{Present: false, Status: "missing"}
			case last == cur:
				targets[tname] = ManifestTarget{Present: true, Status: "in-sync"}
			default:
				targets[tname] = ManifestTarget{Present: true, Status: "drift"}
			}
		}
		m.Keys = append(m.Keys, ManifestKey{
			Name:        SecretName(s.Key),
			Fingerprint: Fingerprint(salt, s.Value),
			UpdatedAt:   s.Meta.UpdatedAt,
			Targets:     targets,
		})
	}
	return m
}
