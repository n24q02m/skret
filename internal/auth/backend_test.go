package auth

import (
	"path/filepath"
	"testing"
)

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
