package auth

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Store persists credentials to ~/.skret/credentials.yaml with 0600 perms.
type Store struct {
	path string
}

// NewStore returns a Store rooted at ~/.skret/credentials.yaml.
func NewStore() *Store {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return &Store{path: filepath.Join(home, ".skret", "credentials.yaml")}
}

// NewStoreWithPath returns a Store at a custom path (for testing).
func NewStoreWithPath(path string) *Store {
	return &Store{path: path}
}

type storeFile struct {
	Version   string                 `yaml:"version"`
	Providers map[string]*Credential `yaml:"providers"`
}

func (s *Store) read() (*storeFile, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &storeFile{Version: "1", Providers: map[string]*Credential{}}, nil
		}
		return nil, fmt.Errorf("auth store: read %q: %w", s.path, err)
	}
	var f storeFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("auth store: parse %q: %w", s.path, err)
	}
	if f.Providers == nil {
		f.Providers = map[string]*Credential{}
	}
	if f.Version == "" {
		f.Version = "1"
	}
	return &f, nil
}

func (s *Store) write(f *storeFile) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("auth store: mkdir: %w", err)
	}
	raw, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("auth store: marshal: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".credentials-*.yaml")
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
	if err := os.Rename(tmpPath, s.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("auth store: rename: %w", err)
	}
	return nil
}

// Save persists a credential, overwriting any existing entry for the same provider.
func (s *Store) Save(cred *Credential) error {
	f, err := s.read()
	if err != nil {
		return err
	}
	f.Providers[cred.Provider] = cred
	return s.write(f)
}

// Load returns the stored credential for a provider or ErrCredentialNotFound.
func (s *Store) Load(provider string) (*Credential, error) {
	f, err := s.read()
	if err != nil {
		return nil, err
	}
	c, ok := f.Providers[provider]
	if !ok {
		return nil, ErrCredentialNotFound
	}
	c.Provider = provider
	return c, nil
}

// Delete removes a provider entry. Missing is not an error.
func (s *Store) Delete(provider string) error {
	f, err := s.read()
	if err != nil {
		return err
	}
	delete(f.Providers, provider)
	return s.write(f)
}

// List returns all stored provider names.
func (s *Store) List() ([]string, error) {
	f, err := s.read()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(f.Providers))
	for k := range f.Providers {
		names = append(names, k)
	}
	return names, nil
}
