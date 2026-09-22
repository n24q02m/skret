package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

// The error branches in keyringBackend read/write/delete are unreachable with
// a healthy OS keyring; MockInitWithError forces them.
func TestKeyringBackendReadIndexError(t *testing.T) {
	keyring.MockInitWithError(errors.New("boom"))
	t.Cleanup(keyring.MockInit)
	b := &keyringBackend{service: t.Name()}
	if _, err := b.read(); err == nil || !strings.Contains(err.Error(), "read index") {
		t.Fatalf("read() err = %v, want read index failure", err)
	}
}

func TestKeyringBackendWriteIndexError(t *testing.T) {
	keyring.MockInitWithError(errors.New("boom"))
	t.Cleanup(keyring.MockInit)
	b := &keyringBackend{service: t.Name()}
	err := b.write(&storeFile{Version: "1", Providers: map[string]*Credential{}})
	if err == nil || !strings.Contains(err.Error(), "set index") {
		t.Fatalf("write() err = %v, want set index failure", err)
	}
}

func TestKeyringBackendDeleteReadError(t *testing.T) {
	keyring.MockInitWithError(errors.New("boom"))
	t.Cleanup(keyring.MockInit)
	b := &keyringBackend{service: t.Name()}
	if err := b.delete("aws"); err == nil || !strings.Contains(err.Error(), "read index") {
		t.Fatalf("delete() err = %v, want propagated read failure", err)
	}
}

func TestKeyringBackendWriteCredSetError(t *testing.T) {
	keyring.MockInitWithError(errors.New("boom"))
	t.Cleanup(keyring.MockInit)
	b := &keyringBackend{service: t.Name()}
	err := b.write(&storeFile{Version: "1", Providers: map[string]*Credential{
		"aws": {Provider: "aws", Method: "access-key", Token: "sek"},
	}})
	if err == nil || !strings.Contains(err.Error(), `set "aws"`) {
		t.Fatalf("write() err = %v, want set cred failure", err)
	}
}
