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

// NewStore returns the credential store. The 0600 file store is the default
// because it is durable and consistent on every platform. The OS keyring is
// strictly opt-in via SKRET_KEYRING=keyring AND only when it round-trips
// reliably — some backends (observed: Windows Credential Manager) accept a
// write and even pass a same-process read-back, yet fail to read it again in
// a later process, which previously destroyed credentials when the file was
// migrated away. The file is never auto-migrated or renamed: it stays the
// source of truth; keyring, when opted in, is just an alternative store.
func NewStore() *Store {
	fb := &fileBackend{path: defaultFilePath()}
	if os.Getenv("SKRET_KEYRING") != "keyring" {
		return &Store{b: fb}
	}
	if !keyringAvailable() {
		return &Store{b: fb} // requested keyring is unreliable -> safe file fallback
	}
	return &Store{b: &keyringBackend{service: keyringService}}
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
