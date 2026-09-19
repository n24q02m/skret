package local

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/keystore"
	"github.com/n24q02m/skret/internal/provider"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

type localFile struct {
	Version string            `yaml:"version"`
	Secrets map[string]string `yaml:"secrets"`
	// Meta holds non-secret per-key metadata; today only the expiry
	// timestamp (RFC3339) written by `set --ttl` / `rotate --ttl`.
	// Older files without this field load unchanged (nil map).
	Meta map[string]string `yaml:"meta,omitempty"`
}

// expiryFor parses the stored expiry for key; ok is false when absent or
// malformed (a malformed entry is ignored rather than failing reads).
func (f *localFile) expiryFor(key string) (time.Time, bool) {
	raw, ok := f.Meta[key]
	if !ok {
		return time.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}

// Provider reads/writes secrets from a local YAML file.
//
// Encryption: when the file on disk is a keystore envelope it is decrypted
// on load and re-encrypted on every save (sticky encDisk), regardless of
// config. When the environment config declares `encrypted: true` (encCfg),
// saves produce an envelope even if the file is still plaintext — the
// declared write-side intent. Plaintext configs with plaintext files behave
// exactly as before (byte-for-byte), keeping the dev default zero-friction.
type Provider struct {
	mu       sync.RWMutex
	filePath string
	data     localFile

	encCfg  bool   // `encrypted: true` in the active env config (write intent)
	encDisk bool   // file on disk is a keystore envelope (sticky)
	keyMat  string // resolved key material ("" until first needed)
	keySrc  string // provenance of keyMat (env/keyring/passphrase)
}

// New creates a local provider from a resolved config.
func New(cfg *config.ResolvedConfig) (provider.SecretProvider, error) {
	absPath, err := filepath.Abs(cfg.File)
	if err != nil {
		return nil, fmt.Errorf("local: resolve path %q: %w", cfg.File, err)
	}

	p := &Provider{filePath: absPath, encCfg: cfg.Encrypted}
	if err := p.load(); err != nil {
		return nil, fmt.Errorf("local: load %q: %w", absPath, err)
	}
	return p, nil
}

func (p *Provider) Name() string { return "local" }

func (p *Provider) Capabilities() provider.Capabilities {
	return provider.Capabilities{Write: true, MaxValueKB: 1024}
}

func (p *Provider) Get(_ context.Context, key string) (*provider.Secret, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	val, ok := p.data.Secrets[key]
	if !ok {
		return nil, fmt.Errorf("local: get %q: %w", key, provider.ErrNotFound)
	}
	s := &provider.Secret{Key: key, Value: val}
	if ts, ok := p.data.expiryFor(key); ok {
		s.Meta.ExpiresAt = ts
	}
	return s, nil
}

func (p *Provider) GetBatch(_ context.Context, keys []string) ([]*provider.Secret, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	secrets := make([]*provider.Secret, 0, len(keys))
	for _, key := range keys {
		if val, ok := p.data.Secrets[key]; ok {
			s := &provider.Secret{Key: key, Value: val}
			if ts, ok := p.data.expiryFor(key); ok {
				s.Meta.ExpiresAt = ts
			}
			secrets = append(secrets, s)
		}
	}
	return secrets, nil
}

func (p *Provider) List(_ context.Context, _ string) ([]*provider.Secret, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	secrets := make([]*provider.Secret, 0, len(p.data.Secrets))
	for k, v := range p.data.Secrets {
		s := &provider.Secret{Key: k, Value: v}
		if ts, ok := p.data.expiryFor(k); ok {
			s.Meta.ExpiresAt = ts
		}
		secrets = append(secrets, s)
	}
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].Key < secrets[j].Key })
	return secrets, nil
}

func (p *Provider) ListNames(_ context.Context, _ string) ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	names := make([]string, 0, len(p.data.Secrets))
	for k := range p.data.Secrets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, nil
}

func (p *Provider) Fingerprint(_ context.Context, _ string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Re-read the file so change detection reflects on-disk edits — the provider
	// otherwise serves the snapshot read at construction. This refresh also
	// means a subsequent List returns the updated values, which is what
	// `run --watch` needs to relaunch the command with the new secrets.
	if err := p.load(); err != nil {
		return "", err
	}
	lines := make([]string, 0, len(p.data.Secrets))
	for k, v := range p.data.Secrets {
		lines = append(lines, k+"="+v)
	}
	return hashLines(lines), nil
}

// hashLines returns a stable sha256 hex digest of lines, independent of order.
func hashLines(lines []string) string {
	sorted := make([]string, len(lines))
	copy(sorted, lines)
	sort.Strings(sorted)
	joined := strings.Join(sorted, "\n")
	return fmt.Sprintf("%x", sha256.Sum256([]byte(joined)))
}

// Set stores the value. Metadata semantics: a non-zero meta.ExpiresAt
// overwrites the stored expiry; a zero ExpiresAt leaves any existing entry
// untouched, so `set KEY v` and `rotate KEY` preserve a previously recorded
// `--ttl` (rotation continues the existing cadence unless --ttl says
// otherwise).
func (p *Provider) Set(_ context.Context, key string, value string, meta provider.SecretMeta) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.data.Secrets == nil {
		p.data.Secrets = make(map[string]string)
	}
	p.data.Secrets[key] = value
	if !meta.ExpiresAt.IsZero() {
		if p.data.Meta == nil {
			p.data.Meta = make(map[string]string)
		}
		p.data.Meta[key] = meta.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return p.save()
}

func (p *Provider) Delete(_ context.Context, key string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.data.Secrets[key]; !ok {
		return fmt.Errorf("local: delete %q: %w", key, provider.ErrNotFound)
	}
	delete(p.data.Secrets, key)
	return p.save()
}

func (p *Provider) GetHistory(_ context.Context, key string) ([]*provider.Secret, error) {
	return nil, provider.ErrCapabilityNotSupported
}

func (p *Provider) Rollback(_ context.Context, key string, version int64) error {
	return provider.ErrCapabilityNotSupported
}

func (p *Provider) Close() error { return nil }

func (p *Provider) load() error {
	raw, err := os.ReadFile(p.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			p.data = localFile{Version: "1", Secrets: map[string]string{}}
			return nil
		}
		return err
	}
	if keystore.Detect(raw) {
		p.encDisk = true
		if err := p.ensureKey(); err != nil {
			return err
		}
		secrets, meta, err := keystore.OpenWithMeta(raw, p.keyMat)
		if err != nil {
			return err
		}
		p.data = localFile{Version: "1", Secrets: secrets, Meta: meta}
		return nil
	}
	p.encDisk = false
	if err := yaml.Unmarshal(raw, &p.data); err != nil {
		return err
	}
	if p.data.Secrets == nil {
		p.data.Secrets = map[string]string{}
	}
	return nil
}

// ensureKey resolves key material at most once per process. The passphrase
// prompt (interactive terminals only) therefore fires once, not on every
// reload — important for `run --watch`, which re-loads on each poll.
func (p *Provider) ensureKey() error {
	if p.keyMat != "" {
		return nil
	}
	res, err := keystore.ResolveKeyMaterial(keystore.ResolveOpts{
		Interactive: term.IsTerminal(int(os.Stdin.Fd())),
	})
	if err != nil {
		return err
	}
	p.keyMat, p.keySrc = res.Material, res.Source
	return nil
}

func (p *Provider) save() error {
	var raw []byte
	var err error
	if p.encCfg || p.encDisk {
		if err := p.ensureKey(); err != nil {
			return err
		}
		raw, err = keystore.SealWithMeta(p.data.Secrets, p.data.Meta, p.keyMat, nil)
		if err != nil {
			return err
		}
	} else {
		raw, err = yaml.Marshal(&p.data)
		if err != nil {
			return fmt.Errorf("local: marshal: %w", err)
		}
	}
	// Atomic write: temp file + rename
	dir := filepath.Dir(p.filePath)
	tmp, err := os.CreateTemp(dir, ".skret-local-*.yaml")
	if err != nil {
		return fmt.Errorf("local: create temp: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("local: write temp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("local: chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("local: close temp: %w", err)
	}
	if err := os.Rename(tmpPath, p.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("local: rename: %w", err)
	}
	return nil
}
