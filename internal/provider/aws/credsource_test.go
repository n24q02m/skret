package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/n24q02m/skret/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestResolveStoredCredentials_SSO(t *testing.T) {
	orig := authStoreLoad
	defer func() { authStoreLoad = orig }()

	// SSO access token expired BY DESIGN (short-lived); validity rests on the
	// refresh token. Must still resolve (not rejected by IsExpired guard).
	authStoreLoad = func(string) (*auth.Credential, error) {
		return ssoCred(time.Now().Add(-time.Hour)), nil
	}
	ref := &fakeRefresher{out: &ssooidc.CreateTokenOutput{
		AccessToken: aws.String("nt"), ExpiresIn: 3600,
	}}
	role := &fakeRole{out: roleOut()}
	var saved []*auth.Credential
	defer withFakes(t, ref, role, &saved)()

	cp, _, ok := resolveStoredCredentials()
	if !ok || cp == nil {
		t.Fatal("sso cred with expired access token must still resolve via ssoProvider")
	}
	got, err := cp.Retrieve(context.Background())
	if err != nil || got.AccessKeyID != "ASIAEXAMPLE" {
		t.Fatalf("retrieve via sso provider failed: err=%v id=%q", err, got.AccessKeyID)
	}

	// Incomplete sso metadata -> fall back to default chain.
	authStoreLoad = func(string) (*auth.Credential, error) {
		c := ssoCred(time.Now().Add(-time.Hour))
		delete(c.Metadata, "refresh_token")
		return c, nil
	}
	if _, _, ok := resolveStoredCredentials(); ok {
		t.Fatal("sso without refresh_token must not resolve")
	}
}

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
		cp, profile, ok := resolveStoredCredentials()
		if !ok || cp == nil {
			t.Fatalf("expected usable provider, got ok=%v cp=%v", ok, cp)
		}
		if profile != "" {
			t.Fatalf("expected empty profile for access-key, got %q", profile)
		}
		got, err := cp.Retrieve(context.Background())
		if err != nil {
			t.Fatalf("retrieve: %v", err)
		}
		if got.AccessKeyID != "AKIAEXAMPLE" || got.SecretAccessKey != "secret-value" || got.SessionToken != "sess-tok" {
			t.Fatalf("credentials mismatch (values redacted): id=%q sessSet=%v", got.AccessKeyID, got.SessionToken != "")
		}
	})

	t.Run("profile method returns profile name", func(t *testing.T) {
		authStoreLoad = func(string) (*auth.Credential, error) {
			return &auth.Credential{
				Method:   "profile",
				Metadata: map[string]string{"profile": "dev"},
			}, nil
		}
		cp, profile, ok := resolveStoredCredentials()
		if !ok || cp != nil || profile != "dev" {
			t.Fatalf("expected ok=true cp=nil profile=dev, got ok=%v cp=%v profile=%q", ok, cp, profile)
		}
	})

	t.Run("profile method with missing profile name", func(t *testing.T) {
		authStoreLoad = func(string) (*auth.Credential, error) {
			return &auth.Credential{
				Method:   "profile",
				Metadata: map[string]string{},
			}, nil
		}
		_, _, ok := resolveStoredCredentials()
		assert.False(t, ok)
	})

	t.Run("no credential -> default chain", func(t *testing.T) {
		authStoreLoad = func(string) (*auth.Credential, error) { return nil, errors.New("not found") }
		if cp, _, ok := resolveStoredCredentials(); ok || cp != nil {
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
		if _, _, ok := resolveStoredCredentials(); ok {
			t.Fatalf("expired credential must not be used")
		}
	})

	t.Run("access-key missing id -> default chain", func(t *testing.T) {
		authStoreLoad = func(string) (*auth.Credential, error) {
			return &auth.Credential{Method: "access-key", Token: "x"}, nil
		}
		if _, _, ok := resolveStoredCredentials(); ok {
			t.Fatalf("incomplete access-key must not be used")
		}
	})

	t.Run("unknown method -> default chain", func(t *testing.T) {
		authStoreLoad = func(string) (*auth.Credential, error) {
			return &auth.Credential{Method: "unknown"}, nil
		}
		_, _, ok := resolveStoredCredentials()
		assert.False(t, ok)
	})
}

type mockSTSClient struct {
	out *sts.GetCallerIdentityOutput
	err error
}

func (m *mockSTSClient) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return m.out, m.err
}

func TestProbe(t *testing.T) {
	origStore := authStoreLoad
	origSTS := newSTSClient
	defer func() {
		authStoreLoad = origStore
		newSTSClient = origSTS
	}()

	t.Run("success", func(t *testing.T) {
		authStoreLoad = func(string) (*auth.Credential, error) {
			return &auth.Credential{
				Method:   "access-key",
				Token:    "secret",
				Metadata: map[string]string{"access_key_id": "AKIA"},
			}, nil
		}
		newSTSClient = func(aws.Config) STSClient {
			return &mockSTSClient{out: &sts.GetCallerIdentityOutput{}}
		}
		err := Probe(context.Background())
		assert.NoError(t, err)
	})

	t.Run("sts error", func(t *testing.T) {
		authStoreLoad = func(string) (*auth.Credential, error) {
			return &auth.Credential{
				Method:   "access-key",
				Token:    "secret",
				Metadata: map[string]string{"access_key_id": "AKIA"},
			}, nil
		}
		newSTSClient = func(aws.Config) STSClient {
			return &mockSTSClient{err: errors.New("sts error")}
		}
		err := Probe(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "sts error")
	})

	t.Run("no credentials still probes default chain", func(t *testing.T) {
		authStoreLoad = func(string) (*auth.Credential, error) { return nil, nil }
		newSTSClient = func(aws.Config) STSClient {
			return &mockSTSClient{out: &sts.GetCallerIdentityOutput{}}
		}
		err := Probe(context.Background())
		assert.NoError(t, err)
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

	creds, _, ok := resolveStoredCredentials()
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
