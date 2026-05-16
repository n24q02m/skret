package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/auth"
)

func TestResolveStoredCredentials(t *testing.T) {
	orig := authStoreLoad
	defer func() { authStoreLoad = orig }()

	t.Run("access-key returns static provider", func(t *testing.T) {
		authStoreLoad = func(string) (*auth.Credential, error) {
			return &auth.Credential{
				Method: "access-key",
				Token:  "secret-value",
				Metadata: map[string]string{
					"access_key_id": "AKIAEXAMPLE",
					"session_token": "sess-tok",
				},
			}, nil
		}
		cp, ok := resolveStoredCredentials()
		if !ok || cp == nil {
			t.Fatalf("expected usable provider, got ok=%v cp=%v", ok, cp)
		}
		got, err := cp.Retrieve(context.Background())
		if err != nil {
			t.Fatalf("retrieve: %v", err)
		}
		if got.AccessKeyID != "AKIAEXAMPLE" || got.SecretAccessKey != "secret-value" || got.SessionToken != "sess-tok" {
			t.Fatalf("credentials mismatch (values redacted): id=%q sessSet=%v", got.AccessKeyID, got.SessionToken != "")
		}
	})

	t.Run("no credential -> default chain", func(t *testing.T) {
		authStoreLoad = func(string) (*auth.Credential, error) { return nil, errors.New("not found") }
		if cp, ok := resolveStoredCredentials(); ok || cp != nil {
			t.Fatalf("expected fallback, got ok=%v", ok)
		}
	})

	t.Run("expired credential -> default chain", func(t *testing.T) {
		authStoreLoad = func(string) (*auth.Credential, error) {
			return &auth.Credential{
				Method:    "access-key",
				Token:     "x",
				ExpiresAt: time.Now().Add(-time.Hour),
				Metadata:  map[string]string{"access_key_id": "AKIA"},
			}, nil
		}
		if _, ok := resolveStoredCredentials(); ok {
			t.Fatalf("expired credential must not be used")
		}
	})

	t.Run("profile method -> default chain (Phase 1 scope)", func(t *testing.T) {
		authStoreLoad = func(string) (*auth.Credential, error) {
			return &auth.Credential{Method: "profile", Metadata: map[string]string{"profile": "dev"}}, nil
		}
		if _, ok := resolveStoredCredentials(); ok {
			t.Fatalf("profile must defer to shared-config/default chain in Phase 1")
		}
	})

	t.Run("access-key missing id -> default chain", func(t *testing.T) {
		authStoreLoad = func(string) (*auth.Credential, error) {
			return &auth.Credential{Method: "access-key", Token: "x"}, nil
		}
		if _, ok := resolveStoredCredentials(); ok {
			t.Fatalf("incomplete access-key must not be used")
		}
	})
}

// TestLoadAWSConfigUsesStoredCredentials proves the full Phase 1 seam:
// a stored access-key flows through resolveStoredCredentials into the live
// aws.Config the SSM client is built from, and profile is ignored when a
// stored credential is present. No network call, no real secret.
func TestLoadAWSConfigUsesStoredCredentials(t *testing.T) {
	orig := authStoreLoad
	defer func() { authStoreLoad = orig }()
	authStoreLoad = func(string) (*auth.Credential, error) {
		return &auth.Credential{
			Method:   "access-key",
			Token:    "stored-secret",
			Metadata: map[string]string{"access_key_id": "AKIASTORED"},
		}, nil
	}

	creds, ok := resolveStoredCredentials()
	if !ok {
		t.Fatal("expected stored credentials")
	}
	cfg, err := loadAWSConfig(context.Background(), "ap-southeast-1", "should-be-ignored", creds)
	if err != nil {
		t.Fatalf("loadAWSConfig: %v", err)
	}
	got, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	if got.AccessKeyID != "AKIASTORED" || got.SecretAccessKey != "stored-secret" {
		t.Fatalf("aws.Config not using stored credentials (id=%q)", got.AccessKeyID)
	}
}
