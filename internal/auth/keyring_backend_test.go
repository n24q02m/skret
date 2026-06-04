package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

// brokenKeyring simulates a Set-OK-but-read-empty backend (observed: Windows
// Credential Manager on the affected machine) — write returns nil but read
// returns nothing. This is the exact data-loss condition Phase 3 hit.
type brokenKeyring struct{}

func (brokenKeyring) read() (*storeFile, error) {
	return &storeFile{Version: "1", Providers: map[string]*Credential{}}, nil
}
func (brokenKeyring) write(*storeFile) error { return nil }
func (brokenKeyring) delete(string) error    { return nil }

// goodKeyring round-trips correctly.
type goodKeyring struct{ store *storeFile }

func (g *goodKeyring) read() (*storeFile, error) {
	if g.store == nil {
		return &storeFile{Version: "1", Providers: map[string]*Credential{}}, nil
	}
	return g.store, nil
}
func (g *goodKeyring) write(f *storeFile) error { g.store = f; return nil }
func (g *goodKeyring) delete(string) error      { return nil }

func TestMigrate_KeyringWriteOkReadEmpty_NoDataLoss(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "credentials.yaml")
	fb := &fileBackend{path: fp}
	if err := fb.write(&storeFile{Version: "1", Providers: map[string]*Credential{
		"aws":     {Provider: "aws", Method: "access-key", Token: "sek"},
		"doppler": {Provider: "doppler", Method: "personal-token", Token: "dp"},
	}}); err != nil {
		t.Fatal(err)
	}

	migrateFileToKeyring(fb, brokenKeyring{})

	// File MUST stay (no rename) — losing it = the data-loss bug.
	if _, err := os.Stat(fp); err != nil {
		t.Fatalf("source file was renamed despite keyring read-back failing: %v", err)
	}
	if _, err := os.Stat(fp + ".migrated"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(".migrated must NOT exist when keyring verification fails")
	}
	got, err := fb.read()
	if err != nil || len(got.Providers) != 2 {
		t.Fatalf("credentials lost from file backend: %+v err=%v", got, err)
	}
}

func TestMigrate_VerifyReadbackOk_RetainsFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "credentials.yaml")
	fb := &fileBackend{path: fp}
	if err := fb.write(&storeFile{Version: "1", Providers: map[string]*Credential{
		"aws": {Provider: "aws", Method: "sso", Token: "t"},
	}}); err != nil {
		t.Fatal(err)
	}

	gk := &goodKeyring{}
	migrateFileToKeyring(fb, gk)

	// File MUST stay (no rename) even after successful migration.
	if _, err := os.Stat(fp); err != nil {
		t.Fatalf("source file was renamed despite successful migration: %v", err)
	}
	if _, err := os.Stat(fp + ".migrated"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(".migrated must NOT exist after migration (source is retained)")
	}
	if g, _ := gk.read(); g.Providers["aws"] == nil || g.Providers["aws"].Token != "t" {
		t.Fatalf("keyring missing migrated data: %+v", g)
	}
}

func TestKeyringAvailable_RoundTripVerified(t *testing.T) {
	keyring.MockInit() // mock round-trips correctly -> available
	if !keyringAvailable() {
		t.Fatal("keyringAvailable must be true when the keyring round-trips")
	}
}

func TestKeyringBackendRoundTrip(t *testing.T) {
	keyring.MockInit() // in-memory; works headless/CI

	b := &keyringBackend{service: "skret-test"}
	in := &storeFile{Version: "1", Providers: map[string]*Credential{
		"aws": {
			Provider: "aws", Method: "access-key", Token: "sek",
			Metadata: map[string]string{"access_key_id": "AKIA"},
		},
	}}
	if err := b.write(in); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := b.read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Providers["aws"].Token != "sek" || got.Version != "1" {
		t.Fatalf("round-trip mismatch: %+v", got.Providers["aws"])
	}
	if got.Providers["aws"].Metadata["access_key_id"] != "AKIA" {
		t.Fatalf("metadata lost: %+v", got.Providers["aws"].Metadata)
	}
	if err := b.delete("aws"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if g2, _ := b.read(); len(g2.Providers) != 0 {
		t.Fatalf("delete did not remove provider: %+v", g2.Providers)
	}
}

func TestKeyringBackendParseError(t *testing.T) {
	keyring.MockInit()
	b := &keyringBackend{service: "skret-bad"}
	if err := keyring.Set(b.service, keyringIndexUser, "aws"); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set(b.service, "cred:aws", "{{{not yaml"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.read(); err == nil {
		t.Fatal("expected parse error for corrupt keyring entry")
	}
}

func TestMigrateNoFileAndEmpty(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	kb := &keyringBackend{service: "skret-mig2"}

	// No file -> no-op (no panic).
	migrateFileToKeyring(&fileBackend{path: filepath.Join(dir, "absent.yaml")}, kb)

	// File with zero providers -> not migrated, file left in place.
	fp := filepath.Join(dir, "empty.yaml")
	fb := &fileBackend{path: fp}
	if err := fb.write(&storeFile{Version: "1", Providers: map[string]*Credential{}}); err != nil {
		t.Fatal(err)
	}
	migrateFileToKeyring(fb, kb)
	if _, err := os.Stat(fp); err != nil {
		t.Fatal("empty file must not be renamed")
	}
	if g, _ := kb.read(); len(g.Providers) != 0 {
		t.Fatal("nothing should have been migrated")
	}
}

func TestKeyringBackendEmptyRead(t *testing.T) {
	keyring.MockInit()
	b := &keyringBackend{service: "skret-empty"}
	f, err := b.read()
	if err != nil {
		t.Fatalf("read empty: %v", err)
	}
	if f.Version != "1" || len(f.Providers) != 0 {
		t.Fatalf("empty read should be a fresh storeFile: %+v", f)
	}
}
