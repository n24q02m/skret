package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awslib "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/n24q02m/skret/internal/auth"
)

type fakeRefresher struct {
	called bool
	out    *ssooidc.CreateTokenOutput
	err    error
}

func (f *fakeRefresher) CreateToken(_ context.Context, _ *ssooidc.CreateTokenInput, _ ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
	f.called = true
	return f.out, f.err
}

type fakeRole struct {
	called bool
	out    *sso.GetRoleCredentialsOutput
	err    error
}

func (f *fakeRole) GetRoleCredentials(_ context.Context, _ *sso.GetRoleCredentialsInput, _ ...func(*sso.Options)) (*sso.GetRoleCredentialsOutput, error) {
	f.called = true
	return f.out, f.err
}

func ssoCred(expiresAt time.Time) *auth.Credential {
	return &auth.Credential{
		Method:    "sso",
		Token:     "old-access-token",
		ExpiresAt: expiresAt,
		Metadata: map[string]string{
			"region": "ap-southeast-1", "refresh_token": "rt-1",
			"client_id": "cid", "client_secret": "csec",
			"account_id": "111122223333", "role_name": "SkretRole",
		},
	}
}

func roleOut() *sso.GetRoleCredentialsOutput {
	return &sso.GetRoleCredentialsOutput{RoleCredentials: &ssotypes.RoleCredentials{
		AccessKeyId:     awslib.String("ASIAEXAMPLE"),
		SecretAccessKey: awslib.String("rolesecret"),
		SessionToken:    awslib.String("sesstok"),
		Expiration:      time.Now().Add(time.Hour).UnixMilli(),
	}}
}

func withFakes(t *testing.T, ref *fakeRefresher, role *fakeRole, saved *[]*auth.Credential) func() {
	t.Helper()
	or, orf, os := newSSORefresher, newSSORoleFetcher, ssoStoreSave
	newSSORefresher = func(string) (ssoTokenRefresher, error) { return ref, nil }
	newSSORoleFetcher = func(string) (ssoRoleFetcher, error) { return role, nil }
	ssoStoreSave = func(c *auth.Credential) error { *saved = append(*saved, c); return nil }
	return func() { newSSORefresher, newSSORoleFetcher, ssoStoreSave = or, orf, os }
}

func TestSSOProvider_ValidToken_NoRefresh(t *testing.T) {
	ref := &fakeRefresher{}
	role := &fakeRole{out: roleOut()}
	var saved []*auth.Credential
	defer withFakes(t, ref, role, &saved)()

	p := &ssoProvider{cred: ssoCred(time.Now().Add(time.Hour))}
	got, err := p.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	if ref.called {
		t.Fatal("refresher must NOT be called when token is still valid")
	}
	if !role.called || got.AccessKeyID != "ASIAEXAMPLE" || got.SecretAccessKey != "rolesecret" {
		t.Fatalf("role creds not returned (id=%q)", got.AccessKeyID)
	}
	if !got.CanExpire {
		t.Fatal("returned credentials must be expiring")
	}
}

func TestSSOProvider_ExpiredToken_RefreshAndPersist(t *testing.T) {
	ref := &fakeRefresher{out: &ssooidc.CreateTokenOutput{
		AccessToken: awslib.String("new-access-token"), ExpiresIn: 3600,
		RefreshToken: awslib.String("rt-2"),
	}}
	role := &fakeRole{out: roleOut()}
	var saved []*auth.Credential
	defer withFakes(t, ref, role, &saved)()

	p := &ssoProvider{cred: ssoCred(time.Now().Add(-time.Minute))}
	got, err := p.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	if !ref.called {
		t.Fatal("refresher MUST be called when token is expired")
	}
	if len(saved) == 0 || saved[len(saved)-1].Token != "new-access-token" ||
		saved[len(saved)-1].Metadata["refresh_token"] != "rt-2" {
		t.Fatalf("store not updated with rotated token: %+v", saved)
	}
	if got.AccessKeyID != "ASIAEXAMPLE" {
		t.Fatalf("role creds not returned (id=%q)", got.AccessKeyID)
	}
}

func TestSSOProvider_RegionFallback(t *testing.T) {
	p := &ssoProvider{cred: &auth.Credential{Method: "sso", Metadata: map[string]string{}}}
	if got := p.region(); got != "us-east-1" {
		t.Fatalf("region fallback = %q, want us-east-1", got)
	}
	p.cred.Metadata["region"] = "eu-west-1"
	if got := p.region(); got != "eu-west-1" {
		t.Fatalf("region = %q, want eu-west-1", got)
	}
}

func TestSSODefaultFactoriesAndStoreSave(t *testing.T) {
	// Default factories build real clients without credentials (no network
	// call until used) — exercises the default closures.
	if r, err := newSSORefresher("us-east-1"); err != nil || r == nil {
		t.Fatalf("newSSORefresher: r=%v err=%v", r, err)
	}
	if rf, err := newSSORoleFetcher("us-east-1"); err != nil || rf == nil {
		t.Fatalf("newSSORoleFetcher: rf=%v err=%v", rf, err)
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("SKRET_KEYRING", "file") // isolate: don't touch the dev OS keyring
	if err := ssoStoreSave(&auth.Credential{Provider: "aws", Method: "sso", Token: "t"}); err != nil {
		t.Fatalf("ssoStoreSave default: %v", err)
	}
}

func TestSSOProvider_RefreshError(t *testing.T) {
	ref := &fakeRefresher{err: errors.New("InvalidGrantException: refresh token expired")}
	role := &fakeRole{out: roleOut()}
	var saved []*auth.Credential
	defer withFakes(t, ref, role, &saved)()

	p := &ssoProvider{cred: ssoCred(time.Now().Add(-time.Minute))}
	_, err := p.Retrieve(context.Background())
	if err == nil {
		t.Fatal("expected refresh error")
	}
	if role.called {
		t.Fatal("role fetcher must NOT be called after refresh failure")
	}
}

func TestSSOProvider_GetRoleError(t *testing.T) {
	ref := &fakeRefresher{}
	role := &fakeRole{err: errors.New("ForbiddenException: no access to role")}
	var saved []*auth.Credential
	defer withFakes(t, ref, role, &saved)()

	p := &ssoProvider{cred: ssoCred(time.Now().Add(time.Hour))}
	_, err := p.Retrieve(context.Background())
	if err == nil {
		t.Fatal("expected get-role error")
	}
}
