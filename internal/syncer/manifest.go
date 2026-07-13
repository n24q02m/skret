package syncer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/n24q02m/skret/internal/provider"
)

// Manifest is the names-only inventory published to the vault hub. It never
// contains secret values — only salted fingerprints, names, and per-target
// presence status.
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
	Status  string `json:"status"` // present | absent | unknown
}

// TargetPresence is what BuildManifest learns about one sync target by
// calling ExistingKeys once (see internal/cli/hub.go's targetPresence,
// which builds this map). Ok=false means the target's existing key names
// could not be determined at all -- either its syncer has no
// ExistingLister implementation (dotenv always; a Cloudflare Pages target),
// or ExistingKeys itself failed (network/API error, or the syncer could
// not even be built, e.g. a missing token) -- in which case every key is
// reported "unknown" for that target rather than making hub push fail
// outright. Names holds the existing key names, uppercased, and is only
// meaningful when Ok is true.
type TargetPresence struct {
	Names map[string]bool
	Ok    bool
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

// BuildManifest computes per-key fingerprint + per-target presence from the
// current SSM secrets and each declared target's TargetPresence (built by
// calling ExistingKeys once per target -- see internal/cli/hub.go's
// targetPresence). GeneratedAt is left zero here — the caller (hub push)
// stamps it once, so the manifest timestamp is set exactly one place.
//
// Per key, per target:
//   - presence.Ok == false                       -> "unknown" (can't tell)
//   - presence.Ok == true, name found in Names    -> "present"
//   - presence.Ok == true, name not found         -> "absent"
func BuildManifest(ns, env string, salt []byte, secrets []*provider.Secret, presence map[string]TargetPresence) *Manifest {
	m := &Manifest{Namespace: ns, Env: env, Keys: make([]ManifestKey, 0, len(secrets))}
	for _, s := range secrets {
		name := SecretName(s.Key)
		targets := map[string]ManifestTarget{}
		for tname, p := range presence {
			switch {
			case !p.Ok:
				targets[tname] = ManifestTarget{Present: false, Status: "unknown"}
			case p.Names[strings.ToUpper(name)]:
				targets[tname] = ManifestTarget{Present: true, Status: "present"}
			default:
				targets[tname] = ManifestTarget{Present: false, Status: "absent"}
			}
		}
		m.Keys = append(m.Keys, ManifestKey{
			Name:        name,
			Fingerprint: Fingerprint(salt, s.Value),
			UpdatedAt:   s.Meta.UpdatedAt,
			Targets:     targets,
		})
	}
	return m
}
