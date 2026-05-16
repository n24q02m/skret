package auth

import (
	"testing"

	"github.com/zalando/go-keyring"
)

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
