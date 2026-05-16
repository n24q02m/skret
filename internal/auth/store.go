package auth

import (
	"os"
	"path/filepath"
)

// Store persists credentials via a pluggable backend (OS keyring when
// available, 0600 file otherwise).
type Store struct{ b backend }

type storeFile struct {
	Version   string                 `yaml:"version"`
	Providers map[string]*Credential `yaml:"providers"`
}

func defaultFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".skret", "credentials.yaml")
}

// NewStore returns a keyring-backed store when an OS keyring is available,
// otherwise the 0600 file store. Set SKRET_KEYRING=file to force the file.
func NewStore() *Store {
	fb := &fileBackend{path: defaultFilePath()}
	if os.Getenv("SKRET_KEYRING") == "file" || !keyringAvailable() {
		return &Store{b: fb}
	}
	kb := &keyringBackend{service: keyringService}
	migrateFileToKeyring(fb, kb) // best-effort, once
	return &Store{b: kb}
}

// NewStoreWithPath returns a file-backed store at a custom path (for testing).
func NewStoreWithPath(path string) *Store {
	return &Store{b: &fileBackend{path: path}}
}

// Save persists a credential, overwriting any existing entry for the same provider.
func (s *Store) Save(cred *Credential) error {
	f, err := s.b.read()
	if err != nil {
		return err
	}
	f.Providers[cred.Provider] = cred
	return s.b.write(f)
}

// Load returns the stored credential for a provider or ErrCredentialNotFound.
func (s *Store) Load(provider string) (*Credential, error) {
	f, err := s.b.read()
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
	return s.b.delete(provider)
}

// List returns all stored provider names.
func (s *Store) List() ([]string, error) {
	f, err := s.b.read()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(f.Providers))
	for k := range f.Providers {
		names = append(names, k)
	}
	return names, nil
}
