package auth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestNewStoreSelectsFileWhenForced(t *testing.T) {
	t.Setenv("SKRET_KEYRING", "file")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	if _, ok := NewStore().b.(*fileBackend); !ok {
		t.Fatal("SKRET_KEYRING=file must select fileBackend")
	}
}

func TestNewStoreDefaultsToFileBackend(t *testing.T) {
	// No SKRET_KEYRING -> durable file store (keyring is opt-in). Prevents the
	// Windows-keyring data-loss regression where keyring was the default.
	t.Setenv("SKRET_KEYRING", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	if _, ok := NewStore().b.(*fileBackend); !ok {
		t.Fatal("NewStore must default to fileBackend when SKRET_KEYRING is unset")
	}
}

func TestNewStoreKeyringOptInUnreliableFallsBackToFile(t *testing.T) {
	orig := keyringAvailable
	defer func() { keyringAvailable = orig }()
	keyringAvailable = func() bool { return false } // unreliable keyring
	t.Setenv("SKRET_KEYRING", "keyring")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	if _, ok := NewStore().b.(*fileBackend); !ok {
		t.Fatal("opt-in keyring that is unreliable must fall back to fileBackend")
	}
}

func TestNewStoreSelectsKeyringWhenAvailable(t *testing.T) {
	orig := keyringAvailable
	defer func() { keyringAvailable = orig }()
	keyringAvailable = func() bool { return true }
	keyring.MockInit()
	t.Setenv("SKRET_KEYRING", "keyring") // keyring is opt-in now
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	if _, ok := NewStore().b.(*keyringBackend); !ok {
		t.Fatal("keyring available must select keyringBackend")
	}
}

func TestMigrateFileToKeyring(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	fp := filepath.Join(dir, "credentials.yaml")
	fb := &fileBackend{path: fp}
	if err := fb.write(&storeFile{Version: "1", Providers: map[string]*Credential{
		"aws": {Provider: "aws", Method: "sso", Token: "t"},
	}}); err != nil {
		t.Fatal(err)
	}
	kb := &keyringBackend{service: "skret-mig"}

	migrateFileToKeyring(fb, kb)

	got, err := kb.read()
	if err != nil || got.Providers["aws"] == nil || got.Providers["aws"].Token != "t" {
		t.Fatalf("not migrated into keyring: %+v err=%v", got, err)
	}
	if _, err := os.Stat(fp); !os.IsNotExist(err) {
		t.Fatal("legacy file should be renamed away")
	}
	if _, err := os.Stat(fp + ".migrated"); err != nil {
		t.Fatalf("backup .migrated missing: %v", err)
	}
	// Idempotent: second call (no file) is a no-op.
	migrateFileToKeyring(fb, kb)
}

func TestFileBackendRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "credentials.yaml")
	b := &fileBackend{path: p}
	in := &storeFile{Version: "1", Providers: map[string]*Credential{
		"aws": {Provider: "aws", Method: "sso", Token: "t"},
	}}
	if err := b.write(in); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := b.read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Providers["aws"].Method != "sso" || got.Version != "1" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if err := b.delete("aws"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if g2, _ := b.read(); len(g2.Providers) != 0 {
		t.Fatalf("delete did not remove provider")
	}
}
