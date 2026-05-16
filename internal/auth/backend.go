package auth

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// backend persists the whole credential store.
type backend interface {
	read() (*storeFile, error)
	write(f *storeFile) error
	delete(provider string) error
}

// fileBackend is the legacy ~/.skret/credentials.yaml store (0600).
type fileBackend struct{ path string }

func (b *fileBackend) read() (*storeFile, error) {
	raw, err := os.ReadFile(b.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &storeFile{Version: "1", Providers: map[string]*Credential{}}, nil
		}
		return nil, fmt.Errorf("auth store: read %q: %w", b.path, err)
	}
	var f storeFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("auth store: parse %q: %w", b.path, err)
	}
	if f.Providers == nil {
		f.Providers = map[string]*Credential{}
	}
	if f.Version == "" {
		f.Version = "1"
	}
	return &f, nil
}

func (b *fileBackend) write(f *storeFile) error {
	if err := os.MkdirAll(filepath.Dir(b.path), 0o700); err != nil {
		return fmt.Errorf("auth store: mkdir: %w", err)
	}
	raw, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("auth store: marshal: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(b.path), ".credentials-*.yaml")
	if err != nil {
		return fmt.Errorf("auth store: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("auth store: write temp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("auth store: chmod: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("auth store: close: %w", err)
	}
	if err := os.Rename(tmpPath, b.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("auth store: rename: %w", err)
	}
	return nil
}

func (b *fileBackend) delete(provider string) error {
	f, err := b.read()
	if err != nil {
		return err
	}
	delete(f.Providers, provider)
	return b.write(f)
}

// --- Temporary stubs (replaced for real in Phase 3 Tasks 2-3) ---

const keyringService = "skret"

type keyringBackend struct{ service string }

func (b *keyringBackend) read() (*storeFile, error) {
	return &storeFile{Version: "1", Providers: map[string]*Credential{}}, nil
}
func (b *keyringBackend) write(*storeFile) error { return nil }
func (b *keyringBackend) delete(string) error    { return nil }

var keyringAvailable = func() bool { return false }

func migrateFileToKeyring(_ *fileBackend, _ *keyringBackend) {}
