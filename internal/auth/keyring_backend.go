package auth

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
	"gopkg.in/yaml.v3"
)

const (
	keyringService   = "skret"
	keyringIndexUser = "__index__"
)

// keyringBackend stores one keyring entry per provider (value = YAML of that
// Credential) plus an index entry listing provider names. Small per-entry
// blobs keep within OS limits (e.g. Windows Credential Manager).
type keyringBackend struct{ service string }

func (b *keyringBackend) read() (*storeFile, error) {
	f := &storeFile{Version: "1", Providers: map[string]*Credential{}}
	idx, err := keyring.Get(b.service, keyringIndexUser)
	if err != nil {
		if err == keyring.ErrNotFound {
			return f, nil
		}
		return nil, fmt.Errorf("auth keyring: read index: %w", err)
	}
	for _, name := range strings.Split(idx, ",") {
		if name == "" {
			continue
		}
		raw, err := keyring.Get(b.service, "cred:"+name)
		if err != nil {
			if err == keyring.ErrNotFound {
				continue
			}
			return nil, fmt.Errorf("auth keyring: read %q: %w", name, err)
		}
		var c Credential
		if err := yaml.Unmarshal([]byte(raw), &c); err != nil {
			return nil, fmt.Errorf("auth keyring: parse %q: %w", name, err)
		}
		c.Provider = name
		f.Providers[name] = &c
	}
	return f, nil
}

func (b *keyringBackend) write(f *storeFile) error {
	names := make([]string, 0, len(f.Providers))
	for name, c := range f.Providers {
		raw, err := yaml.Marshal(c)
		if err != nil {
			return fmt.Errorf("auth keyring: marshal %q: %w", name, err)
		}
		if err := keyring.Set(b.service, "cred:"+name, string(raw)); err != nil {
			return fmt.Errorf("auth keyring: set %q: %w", name, err)
		}
		names = append(names, name)
	}
	if err := keyring.Set(b.service, keyringIndexUser, strings.Join(names, ",")); err != nil {
		return fmt.Errorf("auth keyring: set index: %w", err)
	}
	return nil
}

func (b *keyringBackend) delete(provider string) error {
	f, err := b.read()
	if err != nil {
		return err
	}
	delete(f.Providers, provider)
	_ = keyring.Delete(b.service, "cred:"+provider)
	return b.write(f)
}

// keyringAvailable probes the OS keyring with a throwaway entry. Overridable
// in tests. Returns false on headless Linux/CI without a Secret Service, AND
// on a 3s timeout — a locked/no-GUI macOS Keychain makes the underlying
// `security` CLI block indefinitely, so skret must never wait on it: it falls
// back to the file store instead of hanging.
var keyringAvailable = func() bool {
	probe, err := randomString(16)
	if err != nil {
		return false
	}
	token, err := randomString(32)
	if err != nil {
		return false
	}

	done := make(chan bool, 1)
	go func() {
		if err := keyring.Set(keyringService, probe, token); err != nil {
			done <- false
			return
		}
		// Set succeeding is NOT enough: some backends (observed: Windows
		// Credential Manager on this machine) accept Set but read back
		// empty/different. Require a round-trip match, else treat the keyring
		// as unusable and fall back to the file store.
		got, err := keyring.Get(keyringService, probe)
		_ = keyring.Delete(keyringService, probe)
		done <- err == nil && got == token
	}()
	select {
	case ok := <-done:
		return ok
	case <-time.After(3 * time.Second):
		return false
	}
}

// migrateFileToKeyring moves a legacy ~/.skret/credentials.yaml into the
// keyring exactly once. It NEVER renames or deletes the source file, even
// after a successful migration, to ensure it remains as a durable fallback
// (avoiding data-loss bugs on unreliable keyrings).
func migrateFileToKeyring(fb *fileBackend, kb backend) {
	if _, err := os.Stat(fb.path); err != nil {
		return // nothing to migrate
	}
	f, err := fb.read()
	if err != nil || len(f.Providers) == 0 {
		return
	}
	if err := kb.write(f); err != nil {
		return
	}
	// Read-back verification: keyring must return every provider written.
	got, err := kb.read()
	if err != nil || len(got.Providers) != len(f.Providers) {
		return // do NOT rename — source stays intact
	}
	for name := range f.Providers {
		if got.Providers[name] == nil {
			return
		}
	}
}
